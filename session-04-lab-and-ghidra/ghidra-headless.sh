#!/usr/bin/env bash
# ghidra-headless.sh — import, analyse and extract, without the GUI
#
# Ghidra's auto-analysis is the slow part of Block 2. Run it here, in the break,
# and arrive at the keyboard with a project that is ready and a first pass
# already on disk.
#
#   ./ghidra-headless.sh analyse <binary> [project]   import + full auto-analysis
#   ./ghidra-headless.sh extract <binary>             functions, strings, imports, xrefs
#   ./ghidra-headless.sh decompile <binary> <fn>      one function, as C
#   ./ghidra-headless.sh suspects <binary>            the functions worth opening first
#
# Set GHIDRA_HOME, or let it look in the usual places.
# Everything is static. Nothing here runs the binary.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

find_ghidra() {
  local g="${GHIDRA_HOME:-}"
  [[ -z "$g" ]] && g=$(find "$HOME" /opt /usr/local -maxdepth 4 -name analyzeHeadless -type f 2>/dev/null | head -1)
  g="${g%/support/analyzeHeadless}"
  [[ -x "$g/support/analyzeHeadless" ]] || die "Ghidra not found — set GHIDRA_HOME"
  printf '%s' "$g"
}

GH=$(find_ghidra)
HEADLESS="$GH/support/analyzeHeadless"
PROJDIR="${GHIDRA_PROJECTS:-$HOME/ghidra-projects}"
SCRIPTS="$(mktemp -d)"
trap 'rm -rf "$SCRIPTS"' EXIT

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# Ghidra scripts are Java or Python2-flavoured Jython. Written out at runtime so
# this file stays a single script you can read.
write_scripts() {
cat > "$SCRIPTS/Extract.java" <<'JAVA'
// Dumps functions, strings, imports and xrefs to a target directory.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import java.io.*;

public class Extract extends GhidraScript {
    public void run() throws Exception {
        String out = System.getenv("EXTRACT_DIR");
        if (out == null) out = ".";
        new File(out).mkdirs();

        PrintWriter f = new PrintWriter(out + "/functions.txt");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            f.printf("%s\t%s\t%d\t%d%n", fn.getEntryPoint(), fn.getName(),
                     fn.getBody().getNumAddresses(),
                     fn.getCalledFunctions(monitor).size());
        }
        f.close();

        PrintWriter s = new PrintWriter(out + "/strings.txt");
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (d.hasStringValue()) {
                int refs = getReferencesTo(d.getAddress()).length;
                s.printf("%s\t%d\t%s%n", d.getAddress(), refs,
                         d.getDefaultValueRepresentation().replace("\n", " "));
            }
        }
        s.close();

        PrintWriter im = new PrintWriter(out + "/imports.txt");
        SymbolIterator si = currentProgram.getSymbolTable().getExternalSymbols();
        while (si.hasNext()) {
            Symbol sym = si.next();
            im.printf("%s\t%s%n", sym.getParentNamespace().getName(), sym.getName());
        }
        im.close();
        println("extracted to " + out);
    }
}
JAVA

cat > "$SCRIPTS/Suspects.java" <<'JAVA'
// Ranks functions by how interesting their API usage is. Not a verdict — a
// reading order. Ghidra hands you four hundred FUN_ names and no priority.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class Suspects extends GhidraScript {
    static final Map<String,String[]> G = new LinkedHashMap<String,String[]>();
    static {
        G.put("injection",  new String[]{"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtMapViewOfSection","QueueUserAPC","SetWindowsHookEx"});
        G.put("resolution", new String[]{"GetProcAddress","LoadLibrary","LdrLoadDll","LdrGetProcedureAddress"});
        G.put("anti-analysis", new String[]{"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugString","GetTickCount","QueryPerformanceCounter"});
        G.put("persistence", new String[]{"RegSetValue","RegCreateKey","CreateService","StartService","CreateProcess","ShellExecute"});
        G.put("network",    new String[]{"InternetOpen","InternetConnect","HttpSendRequest","WinHttpOpen","connect","send","recv","URLDownloadToFile"});
        G.put("crypto",     new String[]{"CryptEncrypt","CryptDecrypt","CryptAcquireContext","BCryptEncrypt","CryptGenKey"});
        G.put("credentials",new String[]{"CredEnumerate","LsaOpenPolicy","SamConnect","CryptUnprotectData"});
        G.put("filesystem", new String[]{"CreateFile","WriteFile","DeleteFile","MoveFile","FindFirstFile"});
    }

    public void run() throws Exception {
        List<String[]> rows = new ArrayList<String[]>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            Set<String> tags = new LinkedHashSet<String>();
            int score = 0;
            for (Function callee : fn.getCalledFunctions(monitor)) {
                String n = callee.getName();
                for (Map.Entry<String,String[]> e : G.entrySet())
                    for (String api : e.getValue())
                        if (n.indexOf(api) >= 0) { tags.add(e.getKey()); score += 10; }
            }
            // A function touching three different capability groups is doing
            // something. One group is a library wrapper.
            score += tags.size() * 25;
            if (score > 0)
                rows.add(new String[]{String.valueOf(score), fn.getEntryPoint().toString(),
                                      fn.getName(), tags.toString()});
        }
        Collections.sort(rows, new Comparator<String[]>() {
            public int compare(String[] a, String[] b) {
                return Integer.parseInt(b[0]) - Integer.parseInt(a[0]);
            }});
        println("");
        println("score  address     name                          capability groups");
        println("-----  ----------  ----------------------------  -----------------");
        int n = 0;
        for (String[] r : rows) {
            println(String.format("%5s  %-10s  %-28s  %s", r[0], r[1], r[2], r[3]));
            if (++n >= 25) break;
        }
        println("");
        println("Open the top three. If one of them is still called FUN_, rename it first.");
    }
}
JAVA

cat > "$SCRIPTS/Decompile.java" <<'JAVA'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class Decompile extends GhidraScript {
    public void run() throws Exception {
        String target = System.getenv("DECOMPILE_FN");
        if (target == null) { println("set DECOMPILE_FN"); return; }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        boolean found = false;
        while (it.hasNext()) {
            Function fn = it.next();
            if (!fn.getName().equals(target) && !fn.getEntryPoint().toString().equals(target)) continue;
            found = true;
            DecompileResults r = di.decompileFunction(fn, 60, monitor);
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("decompilation failed: " + r.getErrorMessage());
            break;
        }
        if (!found) println("no function called " + target);
        di.dispose();
    }
}
JAVA
}

run_headless() {  # run_headless <binary> <project> <script> [extra env]
  local bin="$1" proj="$2" script="$3"
  mkdir -p "$PROJDIR"
  "$HEADLESS" "$PROJDIR" "$proj" \
    -import "$bin" -overwrite \
    -scriptPath "$SCRIPTS" -postScript "$script" \
    2>&1 | grep -vE '^(INFO|WARN)\s|Using log4j|JVM|^$' || true
}

cmd_analyse() {
  local bin="${1:-}"; [[ -f "$bin" ]] || die "usage: $0 analyse <binary> [project]"
  local proj="${2:-$(basename "$bin" | tr -cd '[:alnum:]._-')}"
  banner "Auto-analysis" "$(basename "$bin") -> project '$proj'"
  hint "this is the slow part. Start it at the beginning of the break."
  write_scripts
  mkdir -p "$PROJDIR"
  local t0=$SECONDS
  "$HEADLESS" "$PROJDIR" "$proj" -import "$bin" -overwrite \
    2>&1 | grep -iE 'analyz|import|error|exception' | tail -15 | sed 's/^/  /'
  ok "done in $((SECONDS - t0))s — project at $PROJDIR/$proj.gpr"
  hint "next: $0 suspects $bin   (or open the project in the GUI)"
}

cmd_extract() {
  local bin="${1:-}"; [[ -f "$bin" ]] || die "usage: $0 extract <binary>"
  local proj; proj=$(basename "$bin" | tr -cd '[:alnum:]._-')
  local out="ghidra-${proj}-$(stamp)"
  write_scripts
  banner "Extracting" "-> $out/"
  EXTRACT_DIR="$PWD/$out" run_headless "$bin" "$proj" Extract.java | sed 's/^/  /'
  for f in functions strings imports; do
    [[ -f "$out/$f.txt" ]] && printf '  %-12s %s line(s)\n' "$f.txt" "$(wc -l < "$out/$f.txt" | tr -d ' ')"
  done
  say ""
  if [[ -f "$out/strings.txt" ]]; then
    info "strings with the most cross-references — where analysis usually starts"
    sort -t$'\t' -k2 -rn "$out/strings.txt" | head -12 \
      | awk -F'\t' '{printf "  %-12s %3s refs  %s\n", $1, $2, substr($3,1,60)}'
    hint "a string with zero refs is dead weight. One with eleven is a decision point."
  fi
}

cmd_suspects() {
  local bin="${1:-}"; [[ -f "$bin" ]] || die "usage: $0 suspects <binary>"
  local proj; proj=$(basename "$bin" | tr -cd '[:alnum:]._-')
  write_scripts
  banner "Reading order" "ranked by capability groups, not by size"
  run_headless "$bin" "$proj" Suspects.java | sed 's/^/  /'
  say ""
  hint "one capability group is a library wrapper. Three is a function doing something."
  hint "this is a reading order, not a verdict. The verdict comes from reading it."
}

cmd_decompile() {
  local bin="${1:-}" fn="${2:-}"
  [[ -f "$bin" && -n "$fn" ]] || die "usage: $0 decompile <binary> <function-or-address>"
  local proj; proj=$(basename "$bin" | tr -cd '[:alnum:]._-')
  write_scripts
  banner "Decompiling $fn"
  DECOMPILE_FN="$fn" run_headless "$bin" "$proj" Decompile.java
  say ""
  hint "the C is a hypothesis, not sworn testimony. Cross-check anything that"
  hint "goes in a report against the disassembly."
}

case "${1:-}" in
  analyse|analyze) shift; cmd_analyse "$@" ;;
  extract)   shift; cmd_extract "$@" ;;
  suspects)  shift; cmd_suspects "$@" ;;
  decompile) shift; cmd_decompile "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac

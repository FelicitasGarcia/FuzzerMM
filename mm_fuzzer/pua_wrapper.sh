#!/bin/bash
# Resetear el veredicto ANTES de cada ejecucion para evitar valores stale
echo -n "0" > /tmp/mm_verdict

exec /Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA "$1"

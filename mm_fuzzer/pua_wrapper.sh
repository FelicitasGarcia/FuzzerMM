#!/bin/bash
# Resetear el veredicto ANTES de cada ejecucion para evitar valores stale
echo -n "0" > /tmp/mm_verdict

# Convertir los bytes raw a decimal usando os.fsencode (maneja bytes arbitrarios)
DECIMAL=$(python3 -c "
import sys, os
b = os.fsencode(sys.argv[1])
print(int.from_bytes(b, 'big') if b else 0)
" "$1")

if [ $? -ne 0 ]; then
    exit 1
fi

exec /Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA "$DECIMAL"

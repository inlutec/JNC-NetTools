#!/bin/bash

# Obtener el directorio donde está el script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Comprobar si se está ejecutando en una terminal
if [ -t 0 ]; then
    # Estamos en una terminal, pedir sudo directamente
    echo "Iniciando JNC-Scan..."
    sudo ./venv/bin/python3 main.py
else
    # No estamos en una terminal (doble clic), intentar abrir una
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- bash -c "sudo $DIR/venv/bin/python3 main.py; exec bash"
    elif command -v x-terminal-emulator &> /dev/null; then
        x-terminal-emulator -e "sudo $DIR/venv/bin/python3 main.py"
    elif command -v xterm &> /dev/null; then
        xterm -e "sudo $DIR/venv/bin/python3 main.py"
    else
        # Fallback gráfico si no hay terminal detectada (usando pkexec si existe)
        if command -v pkexec &> /dev/null; then
            pkexec $DIR/venv/bin/python3 main.py
        else
            notify-send "Error" "No se encontró una terminal compatible para pedir contraseña de root."
        fi
    fi
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
if [ -t 0 ]; then
    echo "Iniciando JNC-Scan..."
    sudo ./venv/bin/python3 main.py
else
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- bash -c "sudo $DIR/venv/bin/python3 main.py; exec bash"
    elif command -v x-terminal-emulator &> /dev/null; then
        x-terminal-emulator -e "sudo $DIR/venv/bin/python3 main.py"
    elif command -v xterm &> /dev/null; then
        xterm -e "sudo $DIR/venv/bin/python3 main.py"
    else
        if command -v pkexec &> /dev/null; then
            pkexec $DIR/venv/bin/python3 main.py
        else
            notify-send "Error" "No se encontró una terminal compatible para pedir contraseña de root."
        fi
    fi
fi

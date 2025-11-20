import subprocess
import platform

class DiagnosticsManager:
    def __init__(self):
        pass

    def run_ping(self, host, count=4):
        """
        Executes the ping command.
        Returns a generator that yields output lines.
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), host]
        
        return self._run_command(command)

    def run_traceroute(self, host):
        """
        Executes the tracepath command (as replacement for traceroute).
        Returns a generator that yields output lines.
        """
        # Using tracepath as it's more commonly available without root on modern Linux
        command = ['tracepath', host]
        
        return self._run_command(command)

    def run_dns_lookup(self, host, query_type='A'):
        """
        Executes the dig command for DNS lookup.
        Returns a generator that yields output lines.
        """
        command = ['dig', host, query_type]
        
        return self._run_command(command)

    def _run_command(self, command):
        """
        Helper to run a command and yield its output line by line.
        """
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in process.stdout:
                yield line.strip()
                
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            yield f"Error executing command: {str(e)}"

import gdb
from subprocess import check_output, CalledProcessError

class AttachPidofCommand (gdb.Command):
  "Attach to process by name"

  def __init__ (self):
    super (AttachPidofCommand, self).__init__ ("reattach_f",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE, True)

  def invoke (self, arg, from_tty):
    try:
        cmd = 'ps aux | grep \"firefox[ ]-contentproc\" | awk \'{print $2}\''
        pid = check_output(cmd, shell=True).decode("utf-8").strip()
    except CalledProcessError:
        gdb.write('process \'%s\' not found\n' % (arg))
        return
    try:
        gdb.execute('detach', from_tty)
    except:
        pass
    gdb.write('attach to \'%s\' (%s)\n' % (arg, pid))
    gdb.execute('attach %s' % (pid), from_tty)

AttachPidofCommand()

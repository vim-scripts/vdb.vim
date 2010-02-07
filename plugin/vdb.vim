"Coyright (c) 2006-2007 James Dominy
"This software may be distibuted under the terms of the Gnu General Public License (GPL)
"version 3 (or higher)

if ! exists("g:VDBSourced")

let g:VDBSourced = 1
let s:ScriptLocation = expand("<sfile>")

python << >>
import pty
import vim
import thread
import os
import re
import sys
import time
import select
import mimetypes
import subprocess

df = open("/tmp/vdb-debug.log", "w")

class UserInterrupt(Exception):
	pass

def bufvisible(bufnum):
	for w in vim.windows:
		if w.buffer.number == bufnum:
			return True
	return False

def openbuf(bufnum, **kwargs):
	if bufnum is None:
		return False
	i = 0;
	while i < len(vim.windows):
		if vim.windows[i].buffer.number == bufnum:
			vim.command('execute %i . "wincmd w"'%(i+1))
			return True
		i += 1
	if "name" in kwargs:
		if "position" in kwargs and kwargs["position"] == "below":
			vim.command("set splitbelow")
		else:
			vim.command("set nosplitbelow")
		vim.command("%inew %s"%(kwargs["height"], kwargs["name"]))
		if "settings" in kwargs:
			vim.command("setlocal %s"%(kwargs["settings"]))
		return True
	else:
		return False

def openwin(winnum):
	vim.command('execute %s . "wincmd w"'%(winnum))

def removebuf(bufnum):
	if bufnum is None:
		return
	vim.command("bdelete %i"%bufnum.number)

def TermInsert():
	vim.command("setlocal modifiable")
	vim.command("normal G")
	vim.command("startinsert!")
	if vim.current.buffer.number == VDB.outputbuffer.number:
		VDB.outputpromptlen = len(VDB.outputbuffer[-1])

def TermBackspace():
	if vim.current.buffer.number == VDB.debugbuffer.number:
		mincol = VDB.debugpromptlen
	if vim.current.buffer.number == VDB.outputbuffer.number:
		mincol = VDB.outputpromptlen
	col = vim.current.window.cursor[1]
	if col > mincol:
		vim.current.line = vim.current.line[0:col-1]+vim.current.line[col:]

def TermLeftLimit():
	if vim.current.buffer.number == VDB.debugbuffer.number:
		mincol = VDB.debugpromptlen
	if vim.current.buffer.number == VDB.outputbuffer.number:
		mincol = VDB.outputpromptlen
	col = vim.current.window.cursor[1]
	if col <= mincol:
		vim.current.window.cursor = (vim.current.window.cursor[0], mincol)

def TermUp():
	if VDB.debughistorypos > 0:
		if VDB.debughistorypos == len(VDB.debughistory):
			VDB.debughistorycurrent = VDB.debugbuffer[-1][VDB.debugpromptlen:]
		else:
			VDB.debughistory[VDB.debughistorypos] = VDB.debugbuffer[-1][VDB.debugpromptlen:]
		VDB.debughistorypos -= 1
		VDB.debugbuffer[-1] = VDB.debugbuffer[-1][:VDB.debugpromptlen] + VDB.debughistory[VDB.debughistorypos]
		vim.current.window.cursor = (vim.current.window.cursor[0], len(VDB.debugbuffer[-1]))

def TermDown():
	if VDB.debughistorypos < len(VDB.debughistory):
		VDB.debughistory[VDB.debughistorypos] = VDB.debugbuffer[-1][VDB.debugpromptlen:]
		VDB.debughistorypos += 1
		if VDB.debughistorypos == len(VDB.debughistory):
			VDB.debugbuffer[-1] = VDB.debugbuffer[-1][:VDB.debugpromptlen] + VDB.debughistorycurrent
		else:
			VDB.debugbuffer[-1] = VDB.debugbuffer[-1][:VDB.debugpromptlen] + VDB.debughistory[VDB.debughistorypos]
		vim.current.window.cursor = (vim.current.window.cursor[0], len(VDB.debugbuffer[-1]))

def TermDebugSend():
	VDB.debugcommand(VDB.debugbuffer[-1][VDB.debugpromptlen:], False, False)
	VDBUpdateWatches()
	openbuf(VDB.debugbuffer.number)
	vim.command("normal G")
	vim.command("startinsert!")

def TermKeyPress(key):
	if not VDB.running:
		print "The program is no longer running."
		df.write("The program is no longer running.\n"); df.flush()
		return
	if key == "CR":
		VDB.processinput.write("\n")
	else:
		VDB.processinput.write(key)
	VDB.processinput.flush()

def setconsolebuf():
	for k in ["i", "I", "a", "A", "o", "O", "s", "S", "<Ins>"]: #make sure insert operatons position the cursor at the end of the buffer, and capture the current length of the last line
		vim.command("nmap <silent> <buffer> %s :python TermInsert()<CR>"%(k))
	for k in ["r", "R", "p", "P", "d", "D", "x", "X", "c", "C"]: #prevent changes to the buffer from normal mode
		vim.command("nmap <silent> <buffer> %s <Esc>"%(k))
	for k in ["<C-w>"]: #ignore the word wipe
		vim.command("imap <silent> <buffer> %s <C-\><C-O>:python pass<CR>"%(k))
	vim.command("imap <silent> <buffer> <Bs> <C-\><C-O>:python TermBackspace()<CR>") #catch the backspace and make sure it doesn't go back further then the first insert position
	for k in ["<Left>", "<C-Left>", "<S-Left>"]: #catch left and make sure it doesn't go back too far either
		vim.command("inoremap <silent> <buffer> %s <Left><C-\><C-O>:python TermLeftLimit()<CR>"%(k))
	for k in ["<Home>", "<kHome>"]: #send home to the right position
		vim.command("inoremap <silent> <buffer> %s <Home><C-\><C-O>:python TermLeftLimit()<CR>"%(k))
	
	#allow for command history
	for k in ["<Up>", "<PageUp>", "<kPageUp>", "<S-Up>", "<C-Up>"]:
		vim.command("imap <silent> <buffer> %s <C-\><C-O>:python TermUp()<CR>"%(k))
	for k in ["<Down>", "<PageDown>", "<kPageDown>", "<S-Down>", "<C-Down>"]:
		vim.command("imap <silent> <buffer> %s <C-\><C-O>:python TermDown()<CR>"%(k))

def setterminalbuf():
	for k in ["i", "I", "a", "A", "o", "O", "s", "S", "<Ins>"]: #make sure insert operatons position the cursor at the end of the buffer, and capture the current length of the last line
		vim.command("nmap <silent> <buffer> %s :python TermInsert()<CR>"%(k))
	for k in ["r", "R", "p", "P", "d", "D", "x", "X", "c", "C"]: #prevent changes to the buffer from normal mode
		vim.command("nmap <silent> <buffer> %s <Esc>"%(k))
	for k in ["<C-w>"]: #ignore the word wipe
		vim.command("inoremap <silent> <buffer> %s <C-\><C-O>:python pass<CR>"%(k))
	#pass the standard keys straight through
	for k in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{};:,.<>/?":
		vim.command("silent inoremap <silent> <buffer> %s <C-\><C-O>:python TermKeyPress('%s')<CR><Right>"%(k,k))
	vim.command("silent inoremap <silent> <buffer> ' <C-\><C-O>:python TermKeyPress('\\'')<CR>")
	vim.command("silent inoremap <silent> <buffer> \" <C-\><C-O>:python TermKeyPress('\\\"')<CR>")
	vim.command("silent inoremap <silent> <buffer> \ <C-\><C-O>:python TermKeyPress('\\'')<CR>")
	vim.command("silent inoremap <silent> <buffer> \\| <C-\><C-O>:python TermKeyPress('\\|')<CR>")
	#and marshall the other significant keys into ansi escape sequences
	vim.command("silent inoremap <silent> <buffer> <Space> <C-\><C-O>:python TermKeyPress(' ')<CR>")
	vim.command("silent inoremap <silent> <buffer> <CR> <C-\><C-O>:python TermKeyPress('CR')<CR>")
	#Function keys
	#Cursor keys
	#Ins, Del, Home, End, PgUp, Pgdn, Tab, Esc
	#CTRL-keys

class TSession(object):
	def __init__(self, VDBSourceFile, VDBArguments):
		vim.command("wincmd o")
		self.maxheight = vim.current.window.height
		
		self.unmodifiablebuffers = []

		self.sourcebuffer = vim.current.buffer
		self.pid = os.getpid()
		self.executionfile = None
		
		vim.command("%inew %i-debug"%(vim.current.window.height/5+1, self.pid))
		vim.command("setlocal statusline=Console buftype=nofile noswapfile bufhidden=hide")
		self.ready = False
		self.debugbuffer = vim.current.buffer
		setconsolebuf()
		vim.command("inoremap <buffer> <CR> <C-\><C-O>:python TermDebugSend()<CR>")
		self.debughistory = []
		self.debughistorypos = None

		vim.command("e %s-output"%(self.pid))
		vim.command("setlocal statusline=Output buftype=nofile noswapfile bufhidden=hide")
		self.outputbuffer = vim.current.buffer
		setterminalbuf()

		self.watchbuffer = None

		#load appropriate interface depending on extension (using gdb interface for testing)
		interfacelist = [
			{#python
				"valid": mimetypes.guess_type(VDBSourceFile)[0] != None and 'python' in mimetypes.guess_type(VDBSourceFile)[0],
				"executable": "cpdb.py -t %(pty)s %(filename)s %(VDBArguments)s",
				"prompt": "(Pdb) ",
				"autostart": [],
				"stepinto": "step",
				"stepover": "next",
				"continue": "cont",
				"finish": "finish",
				"setbreak": "break %(buffer)s:%(lineno)i",
				"breakpoint": "Breakpoint ([0-9]+) at .*",
				"clearbreak": "delete %(number)i",
				"condition": "condition %(number)i %(condition)s",
				"getsymbolvalue": "p %(symbolname)s",
				"autoresponses": [
					#(tuple of form (pattern to match, filtered line to add to console buffer, action)
					("^> <string>\(1\)\?\(\)->None$", "\\0", self.stop, None),
					("^> (.*)\((\d+)\).*$", "\\0", self.placeexecution, [("filename", "\\1"), ("lineno", "\\2")]),
					("^\$(\d+) = (.*)$", "\\2", None, None),
					("^\032(.*)$", "\\1", None, None),
					("^The program finished and will be restarted$", None, self.stop, None)
				],
				"functions": []
			},				
			{#ruby
				"valid": VDBSourceFile[-2:] == "rb",
				"executable": "vdbruby.sh -t %(pty)s %(filename)s %(VDBArguments)s",
				"prompt": "(rdb) ",
				"autostart": [],
				"stepinto": "step",
				"stepover": "next",
				"continue": "cont",
				"finish": "finish",
				"setbreak": "break %(buffer)s:%(lineno)i",
				"breakpoint": "Set breakpoint ([0-9]+) at .*",
				"clearbreak": "delete %(number)i",
				"condition": "condition %(number)i %(condition)s",
				"getsymbolvalue": "p %(symbolname)s",
				"autoresponses": [
					#(tuple of form (pattern to match, filtered line to add to console buffer, action)
					("^(\\S+):([0-9]+):.*$", "\\1", self.placeexecution, [("filename", "\\1"), ("lineno", "\\2")]),
					("^Program exited.$", None, self.stop, None)
				],
				"functions": []
			},				
			{#gdb
				"valid": mimetypes.guess_type(VDBSourceFile)[0] == None and os.stat(VDBSourceFile).st_mode & 0111 != 0,
				"executable": "gdb -fullname",
				"prompt": "(gdb) ",
				"autostart": [
					"file %(VDBSourceFile)s",
					"set args %(VDBArguments)s",
					"set inferior-tty %(VDBTerminal)s",
					"start"
				],
				"stepinto": "step",
				"stepover": "next",
				"continue": "cont",
				"finish": "finish",
				"setbreak": "break %(buffer)s:%(lineno)i",
				"breakpoint": "Breakpoint ([0-9]+) at .*",
				"clearbreak": "delete %(number)i",
				"condition": "condition %(number)i %(condition)s",
				"getsymbolvalue": "print %(symbolname)s",
				#"executionplacement": "(.+):([0-9]+):[0-9]+:[^:]+:0x[0-9a-f]+",
				#"ignorechars": ["\032"],
				"autoresponses": [
					#(tuple of form (pattern to match, filtered line to add to console buffer, action)
					("^\032\032((.+):([0-9]+):[0-9]+:[^:]+:0x[0-9a-f]+)$", "\\1", self.placeexecution, [("filename", "\\2"), ("lineno", "\\3")]),
					("^\$(\d+) = (.*)$", "\\2", None, None),
					("^Starting program: (.+)$", None, self.start, None),
					("^Program exited normally.$", None, self.stop, None)
				],
				"functions": []
			}
		]

		self.interface = None
		for interface in interfacelist:
			if interface['valid']:
				self.interface = interface
				df.write("Selected interface %s\n"%self.interface["executable"]); df.flush()
				break
		if self.interface == None:
			raise AssertionError('Could not determine appropriate debugger for file %s'%VDBSourceFile)

		self.running = False
		self.executionsignplaced = False

		self.ptymaster, self.ptyslave = pty.openpty()
		self.processoutput = os.fdopen(self.ptymaster, "r", 0)
		self.processinput = os.fdopen(self.ptymaster, "w", 0)
		if vim.eval('exists("g:VDB_ptyname")') == "1":
			self.ptyname = vim.eval('g:VDB_ptyname')
			self.use_outputbuffer = False
		else:
			self.ptyname = os.ttyname(self.ptyslave)
			self.use_outputbuffer = True
		try:
			df.write(str(VDBArguments) + "\n"); df.flush()
			debuggercommand = self.interface["executable"]%{"pty": self.ptyname, "filename": VDBSourceFile, "VDBArguments": VDBArguments}
		except:
			df.write("============================ Error\n"); df.flush()
			df.write("Running debugger command: %s"%(debuggercommand)); df.flush()
			return
		df.write("Running debugger command: %s"%(debuggercommand)); df.flush()
		try:
			self.debuggerprocess = subprocess.Popen(debuggercommand, bufsize=0, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		except OSError, e:
			raise Exception, "Can't execute debugger: %s" % (debuggercommand)
		self.command     = self.debuggerprocess.stdin
		self.debugoutput = self.debuggerprocess.stdout
		self.nextredraw = None
		self.output_tid = thread.start_new_thread(self.outputhandler,())
		self.debug_tid = thread.start_new_thread(self.debughandler,())
		self.outputrefresh_tid = thread.start_new_thread(self.outputrefreshhandler,())
		
		#run interface autostart commands to start debugging, and set up process output to outputpipe
		df.write("TSession.__init__: running autostart commands\n"); df.flush()
		for command in self.interface["autostart"]:
			self.debugcommand(command%{"VDBSourceFile": VDBSourceFile, "VDBArguments": VDBArguments, "VDBTerminal": self.ptyname}, True)
		df.write("TSession.__init__: completed autostart commands\n"); df.flush()
		#set break points in the break point list
		for b in VDBBreakpoint:
			reply = self.debugcommand(self.interface["setbreak"]%(b), True)
			m = re.match(self.interface["breakpoint"], reply[0])
			if m is not None:
				b.number = int(m.group(1))
		self.start()
		df.write("finshed TSession.__init__\n"); df.flush()

	def __del__(self):
		self.nextredraw = -1
		self.outputbuffer.append('')
		curbuf = vim.current.buffer.number
		for buf in self.unmodifiablebuffers:
			vim.command("buffer %i"%(buf))
			vim.command("set modifiable")
		vim.command("buffer %i"%(curbuf))
		removebuf(self.watchbuffer)
		removebuf(self.debugbuffer)
	
	def outputhandler(self):
		df.write("output thread starting\n"); df.flush()
		oc = self.processoutput.read(1)
		try:
			while oc != '':
				if oc == '\r':
					pass
				elif oc == '\n':
					self.outputbuffer.append('')
				else:
					self.outputbuffer[-1] += oc
					self.nextredraw = time.time()+0.25
					#recognise terminal escapes here
					ret = select.select([self.processoutput],[],[],0.1)
					#if self.ready and bufvisible(self.outputbuffer.number):
					if len(ret[0]) == 0:
						cw = vim.eval("winnr()")
						openbuf(self.outputbuffer.number);
						vim.command("normal G$");
						openwin(cw)

				oc = self.processoutput.read(1)
				vim.command("echo \"%s\""%oc)
		except:
			print "output thread exiting because of exception"
			df.write("output thread exiting because of exception\n"); df.flush()

		print "output thread exiting"
		df.write("output thread exiting\n"); df.flush()
	
	def debughandler(self):
		df.write("debug thread starting\n"); df.flush()
		try:
			codematch = re.compile('\\\[\?[0-9]+h')
			escapecode = ''
			c = self.debugoutput.read(1)
			while c != '':
				if escapecode != '':
					escapecode += c
					if codematch.match(escapecode):
						escapecode = ''
				else:
					if ord(c) == 27:
						escapecode = '\\'
					else:
						if c == '\n':
							#df.write("\n"); df.flush()
							for response in self.interface["autoresponses"]:
								#df.write("matching autoresponse: %r\n", response); df.flush()
								m = re.match(response[0], self.debugbuffer[-1])
								if m is not None:
									df.write("matched autoresponse: %r\n"%(response,)); df.flush()
									if response[1] is not None:
										self.debugbuffer[-1] = re.sub("\\\\(\d+)", lambda sm: m.group(int(sm.group(1))), response[1])
									args = {}
									if response[3] is not None:
										for arg in response[3]:
											args[arg[0]] = re.sub("\\\\(\d+)", lambda sm: m.group(int(sm.group(1))), arg[1])
									if response[2] is not None:
										if response[3] is not None:
											response[2](args)
										else:
											response[2]()
									break
							self.debugbuffer.append('')
						else:
							self.debugbuffer[-1] += c
							#df.write(c); df.flush()
						if self.debugbuffer[-1] == self.interface["prompt"]:
							self.ready = True
							self.debugpromptlen = len(self.debugbuffer[-1])
							if bufvisible(self.debugbuffer.number):
								cw = vim.eval("winnr()")
								openbuf(self.debugbuffer.number)
								vim.command("normal G$")
								openwin(cw)
				c = self.debugoutput.read(1)
				self.ready = False
			df.close()
		except Exception, e:
			df.write("vdb.vim:%i %s (debug thread exiting)\n"%(10+sys.exc_info()[2].tb_lineno, e)); df.flush()
			self.ready = True
	
	def outputrefreshhandler(self):
		df.write("output refresh thread starting\n"); df.flush()
		while self.nextredraw != -1:
			if (self.nextredraw != None) and (time.time() > self.nextredraw):
				vim.command("redraw")
				self.nextredraw = None
			time.sleep(0.2)
	
	def debugcommand(self, commandstr, sync=False, echo=True):
		if sync:
			while not self.ready:
				time.sleep(0.1)
			startline = len(self.debugbuffer)
		if self.ready:
			if echo:
				self.debugbuffer[-1] += commandstr
			self.debugbuffer.append('')
			self.command.write(commandstr+"\n")
			df.write(commandstr+"\n"); df.flush()
			self.debughistory.append(commandstr)
			if len(self.debughistory) > 50:
				del self.debughistory[0]
			self.debughistorypos = len(self.debughistory)
			self.ready = False
		if sync:
			while not self.ready:
				time.sleep(0.1)
			return self.debugbuffer[startline:]
	
	def placeexecution(self, args):
		df.write("placeexecution(%r)\n"%(args))
		df.flush()
		cw = vim.eval("winnr()")
		openbuf(self.sourcebuffer.number, name=self.executionfile, height=(self.maxheight/5)*4, settings="nomodifiable", position="below")
		if self.executionfile != None:
			try:
				if self.executionsignplaced:
					vim.command("silent sign jump 65535 file=%s"%(self.executionfile))
					vim.command("sign unplace 65535 file=%s"%(self.executionfile))
					self.executionsignplaced = False
					idx = VDBBreakpointOnLine(vim.current.window.cursor[0])
					if idx is not False:
						if VDBBreakpoint[idx].condition == "":
							vim.command("sign place %i line=%i name=BreakPoint file=%s"%(VDBBreakpoint[idx].signnum,vim.current.window.cursor[0],VDBBreakpoint[idx].buffer))
						else:
							vim.command("sign place %i line=%i name=CondBreakPoint file=%s"%(VDBBreakpoint[idx].signnum,vim.current.window.cursor[0],VDBBreakpoint[idx].buffer))
			except:
				pass
		
		if vim.current.buffer.name != args["filename"]:
			vim.command("silent edit %(filename)s"%(args))
			self.sourcebuffer = vim.current.buffer
		vim.command("setlocal nomodifiable")
		if vim.current.buffer.number not in self.unmodifiablebuffers:
			self.unmodifiablebuffers.append(vim.current.buffer.number)

		vim.command("sign place 65535 line=%(lineno)s name=ExecutionLine file=%(filename)s"%(args))
		self.executionsignplaced = True

		self.executionfile = args["filename"]
		vim.command("silent! sign jump 65535 file=%(filename)s"%(args))
		idx = VDBBreakpointOnLine(vim.current.window.cursor[0])
		if idx is not False:
			vim.command("sign unplace %(signnum)i"%(VDBBreakpoint[idx]))
		vim.command("silent! foldopen")
		vim.command("redraw")
		openwin(cw)

	def getsymbolvalues(self, softupdate = False):
		i = 0;
		while i < len(VDBWatch):
			capture = self.debugcommand(self.interface["getsymbolvalue"]%{"symbolname": VDBWatch[i]}, True)
			VDBWatchResults[i] = capture[0]
			i += 1

	def start(self):
		self.running = True

	def stop(self):
		self.running = False
		try:
			if self.executionsignplaced:
				vim.command("silent sign jump 65535 file=%s"%(self.executionfile))
				vim.command("sign unplace 65535 file=%s"%(self.executionfile))
				self.executionsignplaced = False
		except vim.error:
			pass
		print "The program has stopped."
		df.write("The program has stopped."); df.flush()
	
class TBreakpoint(object):
	def __init__(self, buffer, lineno, signnum, number):
		self.buffer = buffer.name
		self.lineno = lineno
		self.signnum = signnum
		self.number = number
		self.condition = ""
	
	def __getitem__(self, item):
		return self.__getattribute__(item)

def VDBBreakpointOnLine(lineno, buffer=None):
	if buffer is None:
		buffer = vim.current.buffer.name
	for i in range(len(VDBBreakpoint)):
		if VDBBreakpoint[i].lineno == lineno and VDBBreakpoint[i].buffer == buffer:
			return i
	return False

def VDBUpdateWatches(softupdate = False):
	if VDB is not None and VDB.watchbuffer is not None:
		if not softupdate:
			VDB.getsymbolvalues()
		VDB.watchbuffer[:] = ["%s: %s"%(VDBWatch[i], VDBWatchResults[i]) for i in range(len(VDBWatch))]
	
VDB = None
VDBSourceFile = None
VDBArguments = None
VDBBreakpoint = []
VDBBreakpointIdx = None
VDBBreakpointCount = 0
VDBWatch = []
VDBWatchResults = []
#VDBBaseDir = os.path.dirname(vim.eval("s:ScriptLocation"))

def VDBStart():
	global VDBSourceFile, VDBArguments, VDB
	if VDB == None:
		if VDBSourceFile == None:
			try:
				VDBSourceFile = vim.eval("input('Source file to debug: ', '%s', 'file')"%(vim.current.buffer.name))
				VDBArguments = vim.eval("input('Command line arguments: ', '', 'file')")
			except vim.error:
				VDBSourceFile = None
				VDBArguments  = None
				raise UserInterrupt
		VDB = TSession(VDBSourceFile, VDBArguments)
		return True
	return False

def VDBShowConsole():
	try:
		VDBStart()
	except UserInterrupt:
		return
	openbuf(VDB.debugbuffer.number, name="%i-debug"%(VDB.pid), height=(vim.current.window.height/5))

def VDBSendRawInput():
	try:
		VDBStart()
	except UserInterrupt:
		return
	try:
		s = vim.eval("input('Input string: ')")
	except vim.error:
		return
	VDB.processinput.write(s+"\n")
	VDB.processinput.flush()

def VDBUntil():
	global VDBBreakpointCount
	b = TBreakpoint(vim.current.window.buffer, vim.current.window.cursor[0], 65534-VDBBreakpointCount, None)
	VDBBreakpointCount += 1
	try:
		VDBStart()
	except UserInterrupt:
		return
	reply = VDB.debugcommand(VDB.interface["setbreak"]%(b), True)
	m = re.match(VDB.interface["breakpoint"], reply[0])
	if m is not None:
		b.number = int(m.group(1))
		VDB.debugcommand(VDB.interface["continue"])
		VDB.debugcommand(VDB.interface["clearbreak"]%(b))
		VDBUpdateWatches()

def VDBToggleBreak():
	global VDBBreakpointIdx, VDBBreakpointCount
	b = VDBBreakpointOnLine(vim.current.window.cursor[0])
	if b is not False:
		if VDB:
			VDB.debugcommand(VDB.interface["clearbreak"]%(VDBBreakpoint[b]))
		vim.command("sign unplace %(signnum)i"%VDBBreakpoint[b])
		del VDBBreakpoint[b]
	else:
		b = TBreakpoint(vim.current.window.buffer, vim.current.window.cursor[0], 65534-VDBBreakpointCount, None)
		VDBBreakpointCount += 1
		vim.command("sign place %(signnum)i line=%(lineno)i name=BreakPoint file=%(buffer)s"%b)
		VDBBreakpoint.append(b)
		if VDB:
			VDBBreakpointIdx = len(VDBBreakpoint)-1
			reply = VDB.debugcommand(VDB.interface["setbreak"]%(b), True)
			m = re.match(VDB.interface["breakpoint"], reply[0])
			if m is not None:
				b.number = int(m.group(1))

def VDBBreakpointCondition():
	global VDBBreakpointIdx, VDBBreakpointCount
	b = VDBBreakpointOnLine(vim.current.window.cursor[0])
	if b is not False:
		try:
			VDBBreakpoint[b].condition = vim.eval("input('Breakpoint condition: ', '%s')"%VDBBreakpoint[b].condition)
		except vim.error:
			return
		if VDB:
			VDB.debugcommand(VDB.interface["condition"]%(VDBBreakpoint[b]))
	else:
		b = TBreakpoint(vim.current.window.buffer, vim.current.window.cursor[0], 65534-VDBBreakpointCount, None)
		VDBBreakpointCount += 1
		vim.command("sign place %(signnum)i line=%(lineno)i name=BreakPoint file=%(buffer)s"%b)
		try:
			b.condition = vim.eval("input('Breakpoint condition: ', '%s')"%b.condition)
		except vim.error:
			return
		if b.condition == "":
			vim.command("sign place %(signnum)i line=%(lineno)i name=BreakPoint file=%(buffer)s"%(b))
		else:
			vim.command("sign place %(signnum)i line=%(lineno)i name=CondBreakPoint file=%(buffer)s"%(b))
		if VDB:
			VDBBreakpointIdx = len(VDBBreakpoint)-1
			reply = VDB.debugcommand(VDB.interface["setbreak"]%(b), True)
			m = re.match(VDB.interface["breakpoint"], reply[0])
			if m is not None:
				b.number = int(m.group(1))
			VDB.debugcommand(VDB.interface["condition"]%(VDBBreakpoint[b]))

def VDBAddWatch():
	if VDB is None:
		print "A debug session must be running before adding watches"
		return
	if vim.current.buffer.number == VDB.watchbuffer:
		try:
			symbol = vim.eval("input('New watch symbol: ', '%s')"%(VDBWatch[vim.current.window.cursor[0]-1]))
		except vim.error:
			return
		VDBWatch[vim.current.window.cursor[0]-1] = symbol
		VDBWatchResults[vim.current.window.cursor[0]-1] = "Unknown"
	else:
		try:
			symbol = vim.eval("input('New watch symbol: ')")
		except vim.error:
			return
		if symbol not in VDBWatch:
			VDBWatch.append(symbol)
			VDBWatchResults.append("Unknown")
	if VDB.watchbuffer is not None:
		openbuf(VDB.watchbuffer.number, name="%i-watches"%VDB.pid, height=5, settings="statusline=Watches buftype=nofile noswapfile buhidden=hide")
	else:
		vim.command("5new %i-watches"%VDB.pid)
		vim.command("setlocal statusline=Watches buftype=nofile noswapfile bufhidden=hide")
		VDB.watchbuffer = vim.current.buffer
	VDBUpdateWatches()

def VDBMoveWatchUp():
	if vim.current.buffer.number != VDB.watchbuffer:
		return
	pos = vim.current.window.cursor[0]-1
	if pos <= 0:
		return
	(VDBWatch[pos-1], VDBWatch[pos]) = (VDBWatch[pos], VDBWatch[pos-1])
	(VDBWatchResults[pos-1], VDBWatchResults[pos]) = (VDBWatchResults[pos], VDBWatchResults[pos-1])
	VDBUpdateWatches(True)

def VDBMoveWatchDown():
	if vim.current.buffer.number != VDB.watchbuffer:
		return
	pos = vim.current.window.cursor[0]-1
	if pos >= len(VDBWatch)-1:
		return
	(VDBWatch[pos+1], VDBWatch[pos]) = (VDBWatch[pos], VDBWatch[pos+1])
	(VDBWatchResults[pos+1], VDBWatchResults[pos]) = (VDBWatchResults[pos], VDBWatchResults[pos+1])
	VDBUpdateWatches(True)

def VDBDelWatch():
	if vim.current.buffer.number != VDB.watchbuffer.number:
		return
	pos = vim.current.window.cursor[0]-1
	del VDBWatch[pos]
	del vim.current.buffer[pos]

def VDBStepInto():
	try:
		if not VDBStart():
			VDB.debugcommand(VDB.interface["stepinto"])
			VDBUpdateWatches()
	except UserInterrupt:
		return

def VDBStepOver():
	try:
		if not VDBStart():
			VDB.debugcommand(VDB.interface["stepover"])
			VDBUpdateWatches()
	except UserInterrupt:
		return

def VDBFinish():
	if not VDBStart():
		VDB.debugcommand(VDB.interface["finish"])

def VDBContinue():
	try:
		VDBStart()
		VDB.debugcommand(VDB.interface["continue"])
		VDBUpdateWatches()
	except UserInterrupt:
		return

def VDBKill():
	global VDB
	if VDB is not None:
		try:
			if VDB.executionsignplaced:
				vim.command("silent sign jump 65535 file=%s"%(VDB.executionfile))
				vim.command("sign unplace 65535 file=%s"%(VDB.executionfile))
				VDB.executionsignplaced = False
			VDB.__del__()
		except vim.error:
			pass
		VDB = None

def VDBReset():
	global VDBSourceFile, VDBArguments, VDB
	VDBKill()
	VDBSourceFile = None
	VDBArguments = None
	try:
		VDBStart()
	except UserInterrupt:
		return

>>

highlight ExecutionLine term=bold ctermbg=DarkGreen ctermfg=White
highlight ErrorLine term=inverse ctermbg=DarkRed ctermfg=Black
highlight StackLine term=inverse ctermbg=DarkBlue ctermfg=Black
highlight BreakPoint term=inverse ctermbg=DarkCyan ctermfg=Black

sign define ExecutionLine text==> texthl=ExecutionLine linehl=ExecutionLine
sign define ErrorLine text==> texthl=ErrorLine linehl=ErrorLine
sign define StackLine text=<> texthl=StackLine linehl=StackLine
sign define BreakPoint text=! texthl=BreakPoint linehl=BreakPoint
sign define CondBreakPoint text=? texthl=BreakPoint linehl=BreakPoint

command! VDBShowConsole :python VDBShowConsole()
command! VDBSendRawInput :python VDBSendRawInput()
command! VDBUntil :python VDBUntil()
command! VDBToggleBreak :python VDBToggleBreak()
command! VDBBreakpointCondition :python VDBBreakpointCondition()
command! VDBAddWatch :python VDBAddWatch()
command! VDBMoveWatchUp :python VDBMoveWatchUp()
command! VDBMoveWatchDown :python VDBMoveWatchDown()
command! VDBDelWatch :python VDBDelWatch()
command! VDBStepInto :python VDBStepInto()
command! VDBStepOver :python VDBStepOver()
command! VDBFinish :python VDBFinish()
command! VDBContinue :python VDBContinue()
command! VDBKill :python VDBKill()
command! VDBReset :python VDBReset()

function! VDBMapDefaults()
	nmap <silent> <F2>			:VDBShowConsole<CR>
	nmap <silent> <F3>			:VDBSendRawInput<CR>
	nmap <silent> <F4>			:VDBUntil<CR>
	nmap <silent> <F5>			:VDBToggleBreak<CR>
	nmap <silent> <S-F5>		:VDBBreakpointCondition<CR>
	nmap <silent> <F6>			:VDBAddWatch<CR>
	nmap <silent> <S-F6><Up>	:VDBMoveWatchUp<CR>
	nmap <silent> <S-F6><Down>	:VDBMoveWatchDown<CR>
	nmap <silent> <S-F6>		:VDBDelWatch<CR>
	nmap <silent> <F7>			:VDBStepInto<CR>
	nmap <silent> <F8>			:VDBStepOver<CR>
	nmap <silent> <F9>			:VDBContinue<CR>
	nmap <silent> <S-F9>		:VDBFinish<CR>
	nmap <silent> <F10>			:VDBKill<CR>
	nmap <silent> <S-F10>		:VDBReset<CR>
endfunction

endif

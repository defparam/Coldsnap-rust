//! ###############################################################################
//! # Coldsnap-rust is a "Hello World" example of a snapshot fuzzer built in rust #
//! ###############################################################################
//! 
//! Author: Evan Custodio
//! 
//! This module contain a target specified implementation of a snapshot fuzzer

use spawn_ptrace::CommandPtraceSpawn;
use std::process::{Command,exit};
use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::sys::uio::{process_vm_readv,process_vm_writev, IoVec, RemoteIoVec};
use nix::sys::wait::{waitpid,WaitStatus};
use nix::sys::signal::Signal;
use std::fs::read_to_string;
use std::collections::HashMap;
use std::ffi::c_void;
use rand::Rng;
use rand::seq::SliceRandom;
use libc::user_regs_struct;
use std::time::Instant;
use std::ascii::escape_default;
use std::str;
use std::env;

// Target Specific literals
const TARGET_NAME: &str = "target_exec";
const TARGET_ARGS: [&str;1] = ["                "];


/// This is the read_process_memory helper function, This function wraps the libc standard process_vm_readv function
pub fn read_process_memory(pid: i32, address: u64, size: usize, readb: &mut [u8]) -> Result<usize, nix::Error> {
	let local_iov = &[IoVec::from_mut_slice(readb)][..];
	let remote_iov = RemoteIoVec {
							base: address as usize, 
							len: size,
					};
	let remote_iov = &[remote_iov][..];
	process_vm_readv(Pid::from_raw(pid), local_iov, remote_iov)
}

/// This is the read_process_memory helper function, This function wraps the libc standard process_vm_writev function
pub fn write_process_memory(pid: i32, address: u64, size: usize, writeb: &[u8]) -> Result<usize, nix::Error> {
	let local_iov = &[IoVec::from_slice(writeb)][..];
	let remote_iov = RemoteIoVec {
							base: address as usize, 
							len: size,
					};
	let remote_iov = &[remote_iov][..];
	process_vm_writev(Pid::from_raw(pid), local_iov, remote_iov)
}

/// This is a simple search helper function to find needle inside haystack
/// of 2 u8 arrays
pub fn search_bytes(needle: &[u8], haystack: &[u8]) -> Option<usize>{
	haystack.windows(needle.len()).position(|window| window == needle)
}

/// This function converts a byte array to a string while escaping all
/// non-printable characters
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}

/// This is the formal definition of the Breakpoint struct, this struct
/// keeps track of all attached breakpoints in the target process
pub struct Breakpoint {
	pid: i32,
	bpaddr: u64,
	instword: u64,
	attached: bool,
}

/// Implementation of the Breakpoint struct
impl Breakpoint {

	/// The attach function simply applies a breakpoint at the target address
	/// while saving the instruction byte
	pub fn attach(&mut self) {
		// if we are already attached then bail
		if self.attached { return };
		let pid = Pid::from_raw(self.pid);
		
		let bpaddr_by_8 = self.bpaddr & 0xFFFF_FFFF_FFFF_FFF8;
		let bpaddr_ind  = self.bpaddr & 0x7;

		
		// cast address as a pointer
		let addr_ptr: *mut c_void = bpaddr_by_8 as *mut c_void;
		
		// read the specific location in .text
		self.instword = ptrace::read(pid, addr_ptr).unwrap() as u64;
		
		// create a new instruction word with breakpoint added
		let new_instword = (self.instword & !(0xFF << (8*bpaddr_ind) as u64)) | (0xCC << (8*bpaddr_ind) as u64);
		
		// cast a pointer to the new instword
		let new_instword_ptr: *mut c_void = new_instword as *mut c_void;
		
		// write the breakpoint
		unsafe {
			ptrace::write(pid, addr_ptr, new_instword_ptr).expect("Unable to apply breakpoint");
		}

		// set the attached flag
		self.attached = true;
	}

	/// The Detach function simply removes a breakpoint at the target address
	/// while revert the address back to the instruction byte	
	pub fn detach(&mut self) {
	
		// if we are already detached then bail
		if !self.attached { return };
		let pid = Pid::from_raw(self.pid);
		
		let bpaddr_by_8 = self.bpaddr & 0xFFFF_FFFF_FFFF_FFF8;
		let bpaddr_ind  = self.bpaddr & 0x7;

		
		// cast address as a pointer
		let addr_ptr: *mut c_void = bpaddr_by_8 as *mut c_void;
		
		// read the specific location in .text
		let currword = ptrace::read(pid, addr_ptr).unwrap() as u64;
		
		let instbyte = (self.instword >> bpaddr_ind*8) & 0xFF;
		
		// create a new instruction word with breakpoint removed
		let new_instword = (currword & !(0xFF << (8*bpaddr_ind) as u64)) | (instbyte << (8*bpaddr_ind) as u64);
		
		// cast a pointer to the new instword
		let new_instword_ptr: *mut c_void = new_instword as *mut c_void;
		
		// write back with the breakpoint removed
		unsafe {
			ptrace::write(pid, addr_ptr, new_instword_ptr).expect("Unable to remove breakpoint");
		}
		
		// reset the attached flag
		self.attached = false;
	}

	/// The new function creates a new Breakpoint to the target pid and virtual address.
	/// Calling this function will create the breakpoint and auto-attach it
	pub fn new(pid: i32, bpaddr: u64) -> Breakpoint {
		let mut bp = Breakpoint{
			pid: pid,
			bpaddr: bpaddr,
			instword: 0,
			attached: false
		};
		bp.attach();
		bp
	}

}

/// The Snapshot struct is a wrapper around a memory region in a target process
/// with the ability to save and load the memory region. Dead attributes are allowed
/// since the fuzzer parses more information from the memory maps than it uses.
#[allow(dead_code)]
pub struct Snapshot {
	pid: i32,
	startaddr: u64,
	endaddr: u64,
	size: usize,
	permissions: String,
	offset: u64,
	device: String,
	inode: u64,
	name: String,
	localsave: Vec<u8>,
	writable: bool
}

impl Snapshot {
	
	/// The save method creates a local cached copy of this memory region in the fuzzer process
	pub fn save(&mut self) {
		// Lets make sure we allocated enough memory for a local cache
		// of this snapshot
		self.localsave.reserve_exact(self.size);
		
		// Instead of filling the buffer with initial data, lets
		// just initialize the len to capacity
		unsafe { 
			self.localsave.set_len(self.size); 
		};
		
		// Read from remote memory into our local cache
		let res = read_process_memory(self.pid, self.startaddr, self.size, &mut self.localsave);
		match res {
			_ => {()}
		};
	}
	
	/// The load method writes the fuzzer's cached copy of this memory region into the target's process space
	pub fn load(&mut self) {
		// If we found that this memory region is not writeable then bail (perf improvement)
		if !self.writable {
			return;
		}
		
		// Panic if the fuzzer tries to load before a save
		if self.localsave.len() == 0 {
			panic!("cannot load snapshot, no snapshot exists");
		}
		
		// Write from out local cache into the target memory region
		let res = write_process_memory(self.pid, self.startaddr, self.localsave.len(), &self.localsave);
		
		match res {
			Ok(_v) => {()},
			_ => {self.writable = false}
		};
	}

}

/// The SnapshotManger struct is in charge of parsing /proc/id/maps of the target process
/// and creating/managing all Snapshot structs associated with the target process.
/// The fuzzer uses SnapshotManager's methods to save or load all relevant process state
pub struct SnapshotManager {
	pid: i32,
	memspaces: Vec<Snapshot>,
	regs: user_regs_struct,
}


impl SnapshotManager {
	/// In SnapshotManager's new function we create a new snapshop manager by
	/// parsing the /proc/id/maps of the process id in question.
	pub fn new(pid: i32) -> SnapshotManager {
		// form the absolute path to the process maps
		let mappath = format!("/proc/{}/maps",pid);
		// read the maps contents of the process
		let map = read_to_string(&mappath).unwrap();
		// lets keep a holding area for all the snapshot structs
		let mut memspaces: Vec<Snapshot> = Vec::new();
		
		// We have the maps contents of the process in a string, lets parse it
		// First we go line by line
		for line in map.lines() {
			// Then for each line lets collect all the columns
			let columns: Vec<&str>  = line.split_whitespace().collect();
			
			
			
			// Next we parse each column into their respective variables
			let startendaddrs: Vec<&str>   = columns[0].split("-").collect();
			let startaddr: u64 = u64::from_str_radix(startendaddrs[0],16).expect("Issue parsing map start address");
			let endaddr: u64 = u64::from_str_radix(startendaddrs[1],16).expect("Issue parsing map end address");
			let permissions = columns[1];
			let offset: u64 = u64::from_str_radix(columns[2],16).expect("Issue parsing map offset");
			let device = columns[3];
			let inode: u64 = columns[4].parse().expect("Issue parsing map inode");
			let name = if columns.len() < 6 {
				""
			} else {
				columns[5]
			};
			
			// Lastly we create a new Snapshot struct with all our attribute we parsed for this memory region
			let snap = Snapshot {
				pid: pid,
				startaddr: startaddr,
				endaddr: endaddr,
				size: (endaddr-startaddr) as usize,
				permissions: permissions.to_string(),
				offset: offset,
				device: device.to_string(),
				inode: inode,
				name: name.to_string(),
				localsave: Vec::new(),
				writable: true,
			};
			
			// We keep a growing pool of these Snapshot structs
			memspaces.push(snap);
		}

		// Lastly we return the SnapshotManager
		SnapshotManager {
			pid: pid,
			memspaces: memspaces,
			regs: ptrace::getregs(Pid::from_raw(pid)).unwrap()
		}
	}
	
	/// This is the savestate method for all relevant fuzzing Snapshots
	pub fn savestate(&mut self) {
		// For every snapshot that is read/write
		for snap in self.memspaces.iter_mut().filter(|ss| { &ss.permissions[0..2] == "rw"})
		{
			// Save memory into local
			snap.save();
		}
		// Save the current register state
		self.regs = ptrace::getregs(Pid::from_raw(self.pid)).unwrap();
	}
	
	/// This is the loadstate method for all relevant fuzzing Snapshots
	pub fn loadstate(&mut self) {
		// For every snapshot that is read/write
		for snap in self.memspaces.iter_mut().filter(|ss| { &ss.permissions[0..2] == "rw"})
		{
			// Load memory into process
			snap.load();
		}
		// Load the saved register state
		ptrace::setregs(Pid::from_raw(self.pid), self.regs).expect("Unable to set register state");
	}
	
	/// We use the locate method to find the original input payload from memory
	pub fn locate(&self, payload: &[u8]) -> Result<u64, &str> {
		// For every snapshot that is read/write
		for snap in self.memspaces.iter().filter(|ss| { &ss.permissions[0..2] == "rw"})
		{
			// Search for the payload inside the memory window
			let x = search_bytes(payload, &snap.localsave);
			
			// If we match on a location, return the location + base addr
			match x {
				Some(location) => return Ok(location as u64 + snap.startaddr),
				_ => continue, // continue to the next snap if you can't find it
			};
		};
		// Return error if you couldn't find the payload
		Err("Couldn't find payload")
	}
}




/// The Target struct hold all information with respect to the target executable we are fuzzing
pub struct Target {
    pub startpoint: String,
	pub endpoint: String,
	pub startaddr: u64,
	pub endaddr: u64,
	pub pid: i32,
	pub payload_ptr: u64,
	pub cases: u32,
	pub snapmgr: SnapshotManager,
	pub coverage_bps: HashMap<u64, Breakpoint>,
	pub mutation: Vec<u8>,
	pub corpus: Vec<Vec<u8>>,
	pub crashes: Vec<u64>,
	pub starttime: Instant
}

impl Target {

	/// The new function creates a new Target struct and returns it for fuzzing management
	pub fn new() -> Target {
		println!("Forking the target...");
		let executable = env::current_dir().unwrap().display().to_string() + "/" + TARGET_NAME;

		// fork a new child of the target
		let child = Command::new(&executable).args(&TARGET_ARGS).spawn_ptrace().unwrap_or_else(|err| {
			panic!("Error spawning child process {}: {}", TARGET_NAME, err);
		});
		
		
		let pid = Pid::from_raw(child.id() as i32);
		
		println!("Attaching to the target process {}", child.id());

		// Return a Target with mostly default attributes
		Target {
			startpoint: "startf".to_string(),
			endpoint:   "endf".to_string(),
			startaddr: 0,
			endaddr: 0,
			pid:        pid.as_raw(),
			payload_ptr: 0,
			cases: 0,
			snapmgr:    SnapshotManager::new(pid.as_raw()),
			coverage_bps: HashMap::new(),
			mutation: vec![],
			corpus: vec![TARGET_ARGS[0].as_bytes().to_vec()],
			crashes: vec![],
			starttime: Instant::now()
			}
	}
	
	/// The create_initial_state method shall be called once prior to the fuzzing loop in
	/// order to set up our fuzzing harness
	pub fn create_initial_state(&mut self) {
		
		let snapmgr = &self.snapmgr;
		let memspaces = &snapmgr.memspaces;

		// Return the first executable memory space that has target in its name
		let textmem = memspaces.iter().filter(|ss| {
			&ss.permissions[2..3] == "x" && ss.name.contains("target")
			}).collect::<Vec<&Snapshot>>()[0];
			
		// Executable path
		let executable = env::current_dir().unwrap().display().to_string() + "/" + TARGET_NAME;
		
		// Execute nm on our target to retrieve the start and end snapshot addresses
		let output = Command::new("/usr/bin/nm")
                     .arg(&executable)
                     .output()
                     .expect("failed to execute process");
					 
		let output = std::str::from_utf8(&output.stdout).unwrap();
		
		let mut startaddr = 0;
		let mut endaddr = 0;
		
		// We parse out the address based on if the line contains our target function string
		for line in output.lines() {
			if line.contains(&self.startpoint) {
				startaddr = u64::from_str_radix(line.split_whitespace().collect::<Vec<&str>>()[0], 16).unwrap();
			}
			if line.contains(&self.endpoint) {
				endaddr = u64::from_str_radix(line.split_whitespace().collect::<Vec<&str>>()[0], 16).unwrap();
			}
		}
		
		// panic if the parsing failed
		if startaddr == 0 || endaddr == 0 {
			panic!("Cannot find snapshot start and endpoints: {}, {}", &self.startpoint, &self.endpoint);
		}

		// Lets convert the symbolic start / end points with their virtual addresses
		self.startaddr = startaddr - textmem.offset + textmem.startaddr;
		self.endaddr = endaddr - textmem.offset + textmem.startaddr;
	
		// Next we execute objdump to get a list of all the breakpoints in .text of target
		let output = Command::new("/usr/bin/objdump")
					.arg("-d")	
					.arg("-j")
					.arg(".text")
                    .arg(&executable)
                    .output()
                    .expect("failed to execute process");
					 
		let output = std::str::from_utf8(&output.stdout).unwrap();
			
		let pos = output.find(".text").unwrap();
		let output = &output[pos+8..].to_string().replace("\n\n","\n");
		
		self.coverage_bps.clear();
		
		// Our hacky-parser for grapping all instruction locations
		for line in output.lines() {
			if line.chars().last().unwrap() == ':' {continue};
			let bpaddr_s = line.split_whitespace().collect::<Vec<&str>>()[0].replace(":","");
			let bpaddr = u64::from_str_radix(&bpaddr_s, 16).unwrap();
			let bpaddr = bpaddr - textmem.offset + textmem.startaddr; 
			
			// We create/attach a breakpoint for every instruction found
			self.coverage_bps.insert(bpaddr, Breakpoint::new(self.pid, bpaddr));
		}
		
		println!("Applied {} breakpoints for coverage guidance", self.coverage_bps.len());
				
		let pid = Pid::from_raw(self.pid);
		
		// Next we start child execute to the first/subsequent breakpoints until we reach startaddr
		loop {
			// PTrace continue + wait
			ptrace::cont(pid, None).expect("Unable to continue");	
			waitpid(pid, None).expect("Error handing waitpid event");
			
			// Get the register state for the RIP
			let mut regs = ptrace::getregs(pid).unwrap();
			
			// Breaks are always RIP+1 from the breakpoint location, subtract 1
			regs.rip -= 1;
			
			// Grab out Breakpoint object from Hashmap and detach it
			self.coverage_bps.get_mut(&regs.rip).unwrap().detach();
			
			// Set back the modified RIP
			ptrace::setregs(pid, regs).expect("Unable to set register state");
			
			// Are we at the startaddr? no? then continue the loop
			if regs.rip != self.startaddr {
				continue;
			}
			
			// If this break occured at startaddr then bail from this loop, we are good to go
			break;
		}
		
		// We are at startaddr, save current state
		self.snapmgr.savestate();
	
		// Find where our initial test payload is in memory and record that address
		let payload_ptr = self.snapmgr.locate(TARGET_ARGS[0].as_bytes()).unwrap();
		self.payload_ptr = payload_ptr;
		
		// Start the timer to record how fast we fuzz
		self.starttime = Instant::now();
	}
	
	/// method to simply record fuzz case amounts
	pub fn start_case(&mut self) {
		self.cases += 1;
	}
	
	/// This method returns a tuple of number of total breakpoints covered, and total breakpoints period
	pub fn coverage(&mut self) -> (usize, usize) {
		(self.coverage_bps.len() - self.coverage_bps.iter().filter(|(_k,v)| v.attached).count(), self.coverage_bps.len())
	}
	
	/// Our fuzz method simply chooses a random corpus from the corpus pool and randomly mutates 2 random bytes into 2 random values
	pub fn fuzz(&mut self) {
		let mut rng = rand::thread_rng();
		
		// choose a corpus
		let mut mutation = self.corpus.choose(&mut rng).unwrap().clone();
		
		// choose our random indices and values
		let index0 = rng.gen_range(0,mutation.len());
		let byte0 = rng.gen_range(0,255);
		let index1 = rng.gen_range(0,mutation.len());
		let byte1 = rng.gen_range(0,255);
		
		// mutate
		mutation[index0] = byte0;
		mutation[index1] = byte1;
		
		// cache the mutation in case it does something interesting
		self.mutation = mutation;
		
		// Place the mutation into the attack surface
		write_process_memory(self.pid, self.payload_ptr, self.mutation.len(), &self.mutation).expect("Unable to write process memory");
		
		// Continue execution from startaddr
		ptrace::cont(Pid::from_raw(self.pid), None).expect("Unable to continue");
	}
	
	/// our check_fuzz_result method observes if the fuzz mutation created new coverage or crashed the target (or neither)
	pub fn check_fuzz_result(&mut self) {
		loop {
			// Waitpid and decode the event
			let event = waitpid(Pid::from_raw(self.pid), None).unwrap();
			match event {
				// SIGTRAP and SIGSEGV will be returned as a WaitStatus::Stopped
				WaitStatus::Stopped(pid,sig) => {
					// SIGTRAP if we hit a breakpoint
					if sig == Signal::SIGTRAP {
						// Grab the regs
						let mut regs = ptrace::getregs(pid).unwrap();
						regs.rip -= 1;
						
						// Is this endaddr? No? Then it must be new coverage, record it
						if regs.rip != self.endaddr {
							// Detach the breakpoint for this SIGTRAP
							self.coverage_bps.get_mut(&regs.rip).unwrap().detach();
							// Set the regs for RIP-1
							ptrace::setregs(pid, regs).expect("Unable to set register state");
							// Continue execution
							ptrace::cont(Pid::from_raw(self.pid), None).expect("Unable to continue");
							
							// This mutation is interesting, is it in our pool? No? Then add it
							if !self.corpus.iter().any(|v| *v == self.mutation) {
								// adding a clone of the mutation to our corpus pool
								self.corpus.push(self.mutation.clone());
								// Indicate new coverage
								println!("New Corpus: b'{}'", show(&self.mutation));
								// Continue the loop for any other breaks in our way to the endpoint
								continue;
							}
						}
						else {
							// OK, we are at the endpoint. Nothing to do, 
							// lets break out and return to the main fuzz loop
							break;
						}
					}
					else {
						// We got a SIGSEGV, lets check the RIP
						let regs = ptrace::getregs(pid).unwrap();
						
						// Bail if we seen this crash before
						if self.crashes.contains(&regs.rip) {
							break;
						}
						
						// Otherwise keep history of it for later
						self.crashes.push(regs.rip);
						
						// Indicate we found a crash
						println!("\nCRASH! ({:?} @ {:#x}) - Payload: b'{}'\n",sig,regs.rip, show(&self.mutation));
						
						// There are 2 crashes in this design, if we reached it we kill the fuzzer
						if self.crashes.len() >= 2 {
							let elapsed = self.starttime.elapsed().as_secs_f32();
							let cov = self.coverage();
							
							// Print out our fuzzing stats
							println!("Total Fuzz Cases:               {}", self.cases);
							println!("Duration:                       {:.2} seconds", elapsed);
							println!("Instructions Covered:           {} / {} ({:.2}%)",cov.0,cov.1,cov.0 as f32 / cov.1 as f32 * 100.0);
							println!("Fuzz Cases per Second:          {}",self.cases as f32 / elapsed);
							
							// Kill the fuzzer, no issues
							exit(0);
						}
						
						// If we haven't found the second crash then continue the fuzz
						println!("Continuing to fuzz...");
						break;
					}
				
				},
				_ => {
					// Should not really get here in this toy example
					panic!("Unexpected event from waitpid")
				}
			};
		}
	}
	
	/// method to rewind the target state back to startaddr
	pub fn rewind(&mut self) {
		self.snapmgr.loadstate();
	}

}

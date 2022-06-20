use nix::libc::execve;
use nix::unistd::{fork,Pid, ForkResult};
use nix::sys::ptrace;
use core::panic;
use std::env;
use std::ffi::CString;
use std::io::Write;
use nix::sys::wait::waitpid;
use nix::sys::personality;
use nix::sys::personality::Persona;
use std::fs::File;
use std::path::Path;

enum Endianess{
    Big,
    Little
}

const MAGIC: [u8;4] = [0x7f,0x45,0x4c,0x46];

fn get_endianess() -> Endianess{
    let var :u16 = 1;

    if var as u8 == 1{
        return Endianess::Little;
    }
    return Endianess::Big;
}

fn child_setup(elf:&str){

    personality::set(Persona::ADDR_NO_RANDOMIZE).expect("setting persona did not work!");
    
    unsafe {
        // ouf

        let elf = CString::new(elf).unwrap();
        use std::ptr;
        use nix::libc::c_char;

        let argv: &[*const c_char] = &[elf.as_ptr(), elf.as_ptr(), ptr::null()];
        let envp: &[*const c_char] = &[ptr::null()];

        ptrace::traceme().expect("could not issue traceme!");

        // due to traceme(), we will stop at this execve
        execve(elf.as_ptr(),&argv[0],&envp[0]);
    }

    return;
}

fn search_elf_header(pid: Pid,start:u64) -> Option<(u64,u64)>{
    println!("conducting search for ELF header. Starting at 0x{:x?}...",start);
    /*
    search until ELF header is found. Validate via
    signature and entrypoint
    */

    let endianess =  get_endianess();

    let mut addr: u64 = start;
    loop{
        /*if addr % (8*500000) == 0{
            println!("at 0x{:x?}",addr);
        }*/

        let result: i64 = match ptrace::read(pid,addr as *mut _){
            Ok(val) => val,
            Err(_) => {
                // we might not be ata valid addr, skip this.
                addr = match addr.checked_add(8){
                    Some(x) => x,
                    None => break // we've gone through all addresses
                };
                continue;
            }
        };

        let result = match endianess{
            Endianess::Big => result.to_be_bytes(),
            Endianess::Little => result.to_le_bytes()
        };
            
        // todo: iterators, closures
        match result.windows(4).position(|window| window == MAGIC){
            Some(index) => {
                let index = index as u64;
                let elf_start = index as u64+addr+index;
                
                println!("found a possible ELF header at memory 0x{:x?}",elf_start);
                
                
                /* 
                ------

                used to validate ELF header by comparing entrypoint with start RIP, this
                does not work for PIE binaries.
                
                -----

                let parsed_entry: i64 = ptrace::read(pid,(elf_start+24) as *mut _).unwrap();

                println!("parsed entry: 0x{:x?}, rip = 0x{:x?}",parsed_entry,entry_rip);
                
                if parsed_entry != entry_rip as i64{
                */
            
                let offset_sect_headers: u64 = ptrace::read(pid,(elf_start+40) as *mut _).unwrap() as u64;
                let size_sect_header = ptrace::read(pid,(elf_start+58) as *mut _).unwrap() as u16;
                let num_sect_headers = ptrace::read(pid,(elf_start+60) as *mut _).unwrap() as u16;

                println!("section header size: {}",size_sect_header);

                let size_sect_headers = size_sect_header*num_sect_headers;
                let total_bin_size: u64 = offset_sect_headers+size_sect_headers as u64;

                println!("header valid. Binary size = 0x{:x?} bytes",total_bin_size);

                return Some((elf_start,elf_start+total_bin_size));

            },
            None => {}
        }
        addr = match addr.checked_add(8){
            Some(x) => x,
            None => break // we've gone through all addresses
        };
    }
    return None;

}

fn dump_child(pid:Pid){
    println!("dumping child with pid = {}",pid);
    
    match waitpid(pid,None){
        Ok(res) => {println!("target binary stopped: {:?}",res)},
        Err(err) => print!("errror while waitpid: {}",err.desc())
    }

    let current_rip: u64 = ptrace::getregs(pid).expect("could not get current rip value").rip;

    println!("current rip: 0x{:x?}",current_rip);
    

    // Use start to sepcify a starting point for memory search
    let (elf_start,elf_end) = match search_elf_header(pid,0x555555550000){
        Some(x) => x,
        None => {
            println!("could not find ELF header in memory");
            std::process::exit(1);},
    };

    println!("dumping ELF data beginning from memory offset 0x{:x?} to 0x{:x?}...",elf_start,elf_end);
    let required_reads = (elf_end-elf_start) / 8;

    let mut file = match File::create(&Path::new("./dump")){
        Err(e) => panic!("could not create file ./dump: {}",e),
        Ok(file) => file,
    };

    let mut addr : u64 = elf_start;
    let mut toread = required_reads;
    
    while toread > 0{
        
        let buf = match ptrace::read(pid,addr as *mut _){
            Ok(x) => x.to_le_bytes(),
            Err(_) => {
                // maybe this is not mapped. skipt it and read next addr.
                addr += 8;continue;
            }
        };
        
        file.write(&buf).expect("could not write to ./dump");
        addr += 8;
        toread -= 1;
    }

    println!("finished. see ./dump");

}

fn help(){
    println!("pdump <target_elf>");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String>  = env::args().collect();

    if env::args().count() < 2{
        help();
    }
    
    let target_elf = &args[1];

    println!("dumping {}",target_elf);

    match unsafe {fork()}{
        Ok(ForkResult::Child) => {child_setup(target_elf)},
        
        Ok(ForkResult::Parent{child,..}) => { dump_child(child) },
        
        Err(err) => { println!("could not fork: {}",err.desc()) }

    }

}

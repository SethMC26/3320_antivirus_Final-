# Penguin Protector Anti-Malware 

# Quick start
```bash
#clone repo
git clone https://github.com/SethMC26/FeatherstoneVaranoHoltzman_3320_Final.git

#compile program
gcc src/pproc.c -o pproc

#add to user's local binaries
sudo mv pproc /usr/local/bin/pproc
```

# Usage 
Scan a file 
```bash
pproc scan <file_path>
```

Scan a directory
```bash
pproc scan -d <directory_path>
pproc scan -dir <directory_path>
pproc scan --directory <directory_path>
```

Scan entire system
```bash
pproc scan -a
pproc scan --all
```

Add to whitelist?(still WIP) 
```bash
pproc add <file_path>
```
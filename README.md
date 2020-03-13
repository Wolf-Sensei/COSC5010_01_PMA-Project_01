# COSC5010_01_PMA-Project_01
A project to create a basic automated tool to do malware analysis.
### Author
Robert Randolph
### Purpose
The tool will provide a basic analysis and varius features of given files. 
It is able to explore single files, all files in a given directory, and explore subdirectories if desired. 
It will find when the file was compiled, the sections, imports and functions used, and provide a scale for how likely the file is packed or obfuscated. 
### Usage
This tool is run inside a terminal and takes in varius arguments. 
the arguments are: [-s] [-i] [-f] [-e] [paths]
Use [-s] if you want to save the section names. 
Use [-i] if you want to save the import names. 
Use [-f] if you want to save the function names. 
Use [-e] if you want to explore sub directories. 
[paths] is required and is a list of file and directory paths to process. 

An example would be: "python main.py -s -e myfile.exe ./ C:/my/path/to/dir 
This will process myfile.exe, all files in the current directory and its subdirectories, and all files in 'dir' and it's sub directories. 

The output would be several files put inside of a created directory called MalwareAnalysisResults at the current directory location of the terminal. The files inside would be 
000_MalwareAnalysisResults.txt | which is the overall results found for each file 
001_myfile.exe.txt 
002_filename.txt | in ./ 
003_filename.txt | in ./ 
... 
xxx_filenamexxx.txt | in dir or sub directories 
where the "filename" is the name of the file processed. files 001-xxx will only be created if the flags [-s] [i] or [-f] were used, the contents of which will list the names of sections, imports, or functions based on the flags used for that file.
### Requirements
PEfile at 
https://github.com/erocarrera/pefile or 
https://pypi.org/project/pefile/ 
Used "python -m pip install pefile"
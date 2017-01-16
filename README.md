# NSRL-Stripper
A simple utility for stripping out either the SHA-1, MD5 or CRC values alone from the NSRL hash database 

# Background
Saves new output file that contains only the column of hashes you require, suitably formatted for immediate injestion into digital forensic or other data analysis tools. Note that this utility is NOT needed for X-Ways Forensics because it is already intelligent enough to work out from your initialised hash database what values to import. i.e. if you initiliased as SHA-1, it will injest only the SHA-1 values. In other words, XWF does for you, automatically, what this tool does manually. But you may not be fortunate enough to own a license of XWF. You may be using a forensic tool that cannot automatically work out what values to import. And the NSRL hash databases are so large that even tools like Excel, LibreOffice Calc and Notepad++ will fail to open all the millions of lines making it challenging to extract just the SHA-2, or MD5 or CRC values into a single column. Or you may just need to use something else as well as X-Ways Forensics, in which case a tool like this may be of use to you.
                                                         

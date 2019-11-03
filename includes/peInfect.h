#ifndef PE_INFECT_H
# define PE_INFECT_H

# include <stdio.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>

# define IMAGE_SCN_CNT_CODE 0x00000020
# define IMAGE_SCN_MEM_READ 0x40000000
# define IMAGE_SCN_MEM_EXECUTE 0x20000000
# define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 
 
typedef struct {
  uint16_t  machine;        // Magic number
  uint16_t  shnum;          // Sections number
  uint32_t  timestamp;      // File creation date
  uint32_t  symTbl;         // Pointer to symbol table
  uint32_t  symNum;         // Symbols number
  uint16_t  optHeaderSize;  // Optional header size
  uint16_t  flags;          // File flags
}   PE64_Ehdr;

typedef struct {
  uint64_t  name;
  uint32_t  memsz;
  uint32_t  vaddr;
  uint32_t  filesz;
  uint32_t  paddr;
  uint32_t  prelocaddr;
  uint32_t  pLineNumbers;
  uint16_t  relocationCount;
  uint16_t  lineNumbersCount;
  uint32_t  flags;
}   PE64_Shdr;

typedef struct {
  uint16_t  magic;
  uint8_t   majorVersion;
  uint8_t   minorVersion;
  uint32_t  sizeofcode;
  uint32_t  sizeofdata;
  uint32_t  sizeofbss;
  uint32_t  entryPoint;
  uint32_t  baseOfCode;
  /* only in PE32 files
  uint32_t  baseofdata; */
  uint64_t  imageBase;
  uint32_t  sectionAlignment;
  uint32_t  fileAlignment;
  uint16_t  majorOSVersion;
  uint16_t  minorOSVersion;
  uint16_t  majorImageVersion;
  uint16_t  minorImageVersion;
  uint16_t  majorSubsystemVersion;
  uint16_t  minorSubsystemVersion;
  uint32_t  win32VersionValue;
  uint32_t  sizeOfImage;
  uint32_t  sizeOfHeaders;
  uint32_t  checksum;
}   PE64_OptHdr;

typedef struct {
  size_t    size;
  void      *start;
  PE64_Ehdr *header;
}   file;

#endif

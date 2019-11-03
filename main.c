#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 
 
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

static size_t align(size_t size, size_t alignment) {
  return ((size >> 0x9) + alignment);
}

static int   getHeader(const char *filename, file *bin) {
  int         fd;
  struct stat stats;

  if ((fd = open(filename, O_RDONLY)) == -1)
    return (-1);
  if (stat(filename, &stats) == -1)
    return (-1);
  if ((bin->start = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    return (-1);
  bin->size = stats.st_size;
  bin->header = bin->start + *((uint32_t *)(bin->start + 0x3c)) + 4;
  close(fd);
  return (0);
}

static int  getShellcode(file *bin, uint32_t alignment) {
  int         fd;
  struct stat stats;

  if (system("nasm -o shellcode -win64 shellcode.s") == -1)
    return (-1);
  if (stat("shellcode", &stats) == -1)
    return (-1);
  bin->size = stats.st_size;
  if ((fd = open("shellcode", O_RDONLY)) == -1)
    return (-1);
  if ((bin->start = mmap(NULL, align(stats.st_size, alignment), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    return (-1);
  bin->header = NULL;
  close(fd);
  return (0);
}

static int  writeToFile(file bin) {
  int   fd;

  if ((fd = open("./packed.exe", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
    return (-1);
  write(fd, bin.start, bin.size);
  close(fd);
  return (0);
}

static int  copyContent(file *bin, uint32_t loc, void *content, size_t contentSize, int overwrite) {
  void    *newBin;

  if ((newBin = mmap(NULL, contentSize + bin->size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(newBin, bin->start, loc);
  memcpy(newBin + loc, content, contentSize);
  if (overwrite) {
    memcpy(newBin + loc + contentSize, ((void *)bin->start) + loc + contentSize, bin->size - loc - contentSize);
  } else {
    memcpy(newBin + loc + contentSize, ((void *)bin->start) + loc, bin->size - loc);
  }
  munmap(bin->start, bin->size);
  bin->start = newBin;
  bin->size += contentSize;
  bin->header = bin->start + *((uint32_t *)(bin->start + 0x3c)) + 4;
  return (0);
}

static int  resizeCodeSection(file *bin, file shellcode) {
  size_t      i;
  PE64_Shdr   *shHeader;
  PE64_OptHdr *optHeader;
  PE64_Shdr   *codeSection;

  optHeader = ((void *)bin->header) + sizeof(PE64_Ehdr);
  shHeader = ((void *)optHeader) + bin->header->optHeaderSize;
  copyContent(bin, shHeader->paddr + shHeader->memsz, shellcode.start, align(shellcode.size, optHeader->fileAlignment), 0);
  optHeader = ((void *)bin->header) + sizeof(PE64_Ehdr);
  optHeader->sizeofcode += shellcode.size;
  optHeader->sizeOfImage += shellcode.size;
  shHeader = ((void *)optHeader) + bin->header->optHeaderSize;
  shHeader->memsz += shellcode.size;
  shHeader->filesz += align(shellcode.size, optHeader->fileAlignment);
  bin->header->symTbl += align(shellcode.size, optHeader->fileAlignment);
  i = 0;
  codeSection = ((void *)optHeader) + bin->header->optHeaderSize;
  while (i < bin->header->shnum) {
    shHeader = ((void *)optHeader) + bin->header->optHeaderSize + sizeof(PE64_Shdr) * i;
    if (shHeader->paddr > codeSection->paddr + (codeSection->memsz - align(shellcode.size, optHeader->fileAlignment)))
      shHeader->paddr += optHeader->fileAlignment;
    i += 1;
  }
  return (0);
}

int     main(int argc, const char **argv) {
  file          bin;
  file          shellcode;
  PE64_OptHdr   *optHeader;
  PE64_Shdr     *sectionHeader;

  if (argc != 2) {
    dprintf(2, "Not right number or arguments\n");
    return (1);
  }
  if (getHeader(argv[1], &bin) == -1)
    return (1);
  optHeader = ((void *)bin.header) + sizeof(PE64_Ehdr);
  optHeader->checksum = 0;
  if (getShellcode(&shellcode, optHeader->fileAlignment) == -1)
    return (1);
  if (resizeCodeSection(&bin, shellcode) == -1)
    return (1);
  if (writeToFile(bin) == -1)
    return (-1);
  munmap(bin.start, bin.size);
  munmap(shellcode.start, shellcode.size);
  dprintf(1, "Done !\n");
  return (0);
}

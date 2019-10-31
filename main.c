#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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
  uint32_t  ptLoad;
}   PE64_OptHdr;

typedef struct {
  size_t    size;
  void      *start;
  PE64_Ehdr *header;
}   file;

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

static int  getShellcode(file *bin) {
  int         fd;
  struct stat stats;

  if (system("nasm -o shellcode -win64 shellcode.s") == -1)
    return (-1);
  if (stat("shellcode", &stats) == -1)
    return (-1);
  bin->size = stats.st_size;
  if ((fd = open("shellcode", O_RDONLY)) == -1)
    return (-1);
  if ((bin->start = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    return (-1);
  dprintf(2, "Hex here: %x\n", *((char *)bin->start));
  bin->header = NULL;
  close(fd);
  return (0);
}

static int  updateOffsets(file bin, size_t size) {
  size_t      i;
  uint32_t    paddr;
  PE64_Shdr   *section;
  PE64_OptHdr *optHeader;

  i = 0;
  optHeader = ((void *)bin.header) + sizeof(PE64_Ehdr);
  section = ((void *)optHeader) + bin.header->optHeaderSize;
  paddr = section->paddr;
  while (i < bin.header->shnum) {
    if (section->paddr > paddr) {
      dprintf(1, "Updating offset of ");
      write(1, &(section->name), 8);
      dprintf(1, "\n");
      section->paddr += size;
    }
    section = ((void *)section) + sizeof(PE64_Shdr);
    i += 1;
  }
  return (0);
}

static int  createNewBin(file bin, file shellcode) {
  int   fd;
  void *newBin;
  PE64_OptHdr *optHeader;
  PE64_Shdr   *sectionHeader;

  optHeader = ((void *)bin.header) + sizeof(PE64_Ehdr);
  sectionHeader = ((void *)bin.header) + sizeof(PE64_Ehdr) + bin.header->optHeaderSize;
  if ((newBin = mmap(NULL, bin.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  /* memcpy(newBin, bin.start, 0xae0); */
  /* memcpy(newBin + 0xae0, shellcode.start, shellcode.size); */
  /* memcpy(newBin + 0xae0 + shellcode.size, bin.start + 0xae0 + shellcode.size, bin.size - 0xae0 - shellcode.size); */

  /* memcpy(newBin, bin.start, bin.size); */
  /* memcpy(newBin, shellcode.start, shellcode.size); */

  dprintf(1, "Shellcode size: %zu\n", shellcode.size);
  optHeader->sizeofcode += shellcode.size;
  sectionHeader->filesz += shellcode.size;
  sectionHeader->memsz += shellcode.size;
  memcpy(newBin, bin.start, sectionHeader->paddr + sectionHeader->filesz - shellcode.size);
  memcpy(newBin + sectionHeader->filesz - shellcode.size, shellcode.start, shellcode.size);
  memcpy(newBin + sectionHeader->filesz, bin.start + sectionHeader->paddr + sectionHeader->filesz - shellcode.size, bin.size - sectionHeader->paddr + sectionHeader->filesz - shellcode.size);
  if ((fd = open("./packed.exe", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
    return (1);
  bin.start = newBin;
  bin.header = newBin + *((uint32_t *)(newBin + 0x3c)) + 4;
  bin.size += shellcode.size;
  updateOffsets(bin, shellcode.size);
  write(fd, newBin, bin.size);
  close(fd);
  munmap(newBin, bin.size);
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
  sectionHeader = ((void *)bin.header) + sizeof(PE64_Ehdr) + bin.header->optHeaderSize;
  optHeader = ((void *)bin.header) + sizeof(PE64_Ehdr);
  write(1, &(sectionHeader->name), 8);
  dprintf(1, "Entry point in file offset: %p\n", sectionHeader->paddr + (optHeader->entryPoint - sectionHeader->vaddr));
  if (getShellcode(&shellcode) == -1)
    return (1);
  dprintf(1, "Old Entry point: %p\n", NULL + optHeader->entryPoint);
  /* optHeader->entryPoint = bin.size + 1; */
  dprintf(1, "New entry point: %p\n", NULL + optHeader->entryPoint);
  if (createNewBin(bin, shellcode) == -1)
    return (1);
  munmap(bin.start, bin.size);
  munmap(shellcode.start, shellcode.size);
  dprintf(1, "Done !\n");
  return (0);
}

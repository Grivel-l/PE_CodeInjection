#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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

int     main(int argc, char **argv) {
  int           fd;
  struct stat   stats;
  void          *start;
  PE64_Ehdr     *header;
  PE64_OptHdr   *optHeader;
  PE64_Shdr     *sectionHeader;

  if (argc != 2) {
    dprintf(2, "Not right number or arguments\n");
    return (1);
  }
  fd = open(argv[1], O_RDONLY);
  if (stat(argv[1], &stats) == -1)
    return (1);
  if ((start = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    return (1);
  /* dprintf(1, "Header: %i, %i, %i, %i,%i,%i,%i\n", header->machine, header->shnum, header->timestamp, header->symTbl, header->symNum, header->optHeaderSize, header->flags); */
  header = start;
  uint32_t yo;
  yo = *((uint32_t *)(((void *)header) + 0x3c));
  header = ((void *)header) + yo + 4;
  /* dprintf(1, "Header: %i, %i, %i, %i,%i,%i,%i\n", header->machine, header->shnum, header->timestamp, header->symTbl, header->symNum, header->optHeaderSize, header->flags); */
  sectionHeader = ((void *)header) + sizeof(PE64_Ehdr) + header->optHeaderSize;
  optHeader = ((void *)header) + sizeof(PE64_Ehdr);
  dprintf(1, "Entry point: %p\n", NULL + optHeader->entryPoint);
  write(1, &(sectionHeader->name), 8);
  close(fd);
  if ((fd = open("./packed.exe", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
    return (1);
  write(fd, start, stats.st_size);
  close(fd);
  munmap(start, stats.st_size);
  return (0);
}

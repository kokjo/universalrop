import unicorn

class Emulator:
    def __init__(self, arch):
        self.arch = arch
        self.uc = unicorn.Uc(
                self.arch.unicorn_arch,
                self.arch.unicorn_mode
            )

    def __getitem__(self, reg):
        return self.uc.reg_read(self.arch.unicorn_regs[reg])

    def __setitem__(self, reg, val):
        return self.uc.reg_write(self.arch.unicorn_regs[reg], val)

    def map_addr(self, address, length):
        page = address & self.arch.page_mask
        size = 0
        while page + size <= address + length:
            size += self.arch.page_size
        try:
            self.uc.mem_map(page, size)
        except unicorn.unicorn.UcError as e:
            pass

    def map_code(self, address, code):
        self.map_addr(address, len(code))
        self.uc.mem_write(address, code)

    def setup_stack(self, address, size, data=None):
        self.uc.mem_map(address, size)
        if data:
            self.uc.mem_write(address, data)
        self[self.arch.stack_pointer] = address

    def run(self, address, size):
        try:
            self.uc.emu_start(address, address+size)
        except unicorn.unicorn.UcError as e:
            pass

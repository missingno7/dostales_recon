/* End-to-end native data and external far-call OMF/link probe, not game source. */
extern unsigned asm_mix(unsigned);
unsigned initialized_data = 0x4321;
int main(void)
{
    return asm_mix(initialized_data) != (0x4321 ^ 0x1234);
}

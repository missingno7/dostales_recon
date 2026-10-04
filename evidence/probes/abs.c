/* Standalone source hypothesis for the stock abs contribution at root+0x8410.
 * Matching this does not prove the original game translation unit. */
int abs(int value)
{
    return value >= 0 ? value : -value;
}

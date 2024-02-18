ENTRY( _start )

MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
  RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{
  .init :
  {
    KEEP(*(SORT_NONE(.init)))
  } >FLASH AT>FLASH

  ASSERT(. == 0x38, "Expected to be at address 0x200!")

  .vector :
  {
    *(.vector);
    . = ALIGN(64);
  } >FLASH AT>FLASH

  ASSERT(. == 0x200, "Expected to be at address 0x200!")

  .text :
  {
    *(.text)
  } >FLASH AT>FLASH

  .data :
  {
    *(.data)
  } >RAM AT>FLASH
}

# Per-build decryptor mutation coverage

The production decryptor has six independent mutation dimensions.  The first
dimension selects one of eight xorshift triples; the other five select the
instruction spelling used by the byte-at-a-time inverse transform.  The old
`instructionVariant` byte was not a meaningful "six-bit coverage" claim: some
values selected the same live bytes.  It is now a dense index over the actual
Cartesian product, so every accepted value names one distinct active loop.

## Xorshift dimension

The state transition is always `s ^= s << A; s ^= s >> B; s ^= s << C` and
selects exactly one of these ordered triples:

| Shift-plan index | A | B | C |
|---:|---:|---:|---:|
| 0 | 13 | 7 | 17 |
| 1 | 7 | 9 | 13 |
| 2 | 17 | 11 | 5 |
| 3 | 5 | 15 | 21 |
| 4 | 11 | 5 | 23 |
| 5 | 19 | 3 | 7 |
| 6 | 23 | 13 | 9 |
| 7 | 3 | 17 | 25 |

The x64 loop applies those shifts directly to a 64-bit register.  The x86
loop implements the same modulo-2^64 transition over a high/low 32-bit pair;
it does not truncate the cipher state to 32 bits.

## Five instruction-spelling dimensions

| Dimension | Value 0 | Value 1 | Value 2 |
|---|---|---|---|
| inverse rotate | `ROL AL, 8-r` | `ROR AL, r` | — |
| inverse add | `ADD AL, -addByte` | `SUB AL, addByte` | — |
| XOR low state byte, x64 | `MOV EDX,R12D; XOR AL,DL` | `XOR AL,R12B` | — |
| XOR low state byte, x86 | `MOV DL,[EBP-14h]; XOR AL,DL` | `XOR AL,[EBP-14h]` | — |
| pointer increment, x64 | `INC RSI` | `ADD RSI,1` | `LEA RSI,[RSI+1]` |
| pointer increment, x86 | `INC ESI` | `ADD ESI,1` | `LEA ESI,[ESI+1]` |
| counter decrement, x64 | `SUB EDI,1` | `DEC EDI` | — |
| counter decrement, x86 | `SUB dword [EBP-1Ch],1` | `DEC dword [EBP-1Ch]` | — |

The dense plan index is decoded in this order:

`rotate(2) * add(2) * xor-load(2) * pointer(3) * counter(2) = 48`

Combined with the eight shift triples, production therefore has 384 active
decryptor loops per architecture.  `VM_DECRYPTOR_SHIFT_PLANS` and
`VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT` are the single source of truth shared by
derivation, code generation, byte validation, and the execution test.

## Evidence boundary

`test_vm_decryptor_coverage` generates all 384 plans for its build
architecture, independently encrypts a non-aligned 0x301-byte corpus, executes
the generated decryptor from executable memory, and checks plaintext equality,
state publication, and the RW -> instruction-cache flush -> RX callback
sequence.  It also requires all 384 active-loop byte strings to be unique and
corrupts one shift immediate and one instruction suffix to prove that the
production exact-byte validator rejects both mutations.  The Windows CI matrix
builds/runs this target for x64 and x86, so the two architecture-specific
encodings are covered separately.

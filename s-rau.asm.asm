.ORIG x3000
TitleMessage .STRINGZ "Starting Security Module"
MenuMessage .STRINGZ "ENTER: E TO ENCRYPT, D TO DECRYPT, X TO EXIT"
LEA R0, TitleMessage
TRAP x22
AND R0, R0, #0 ; initializes R0 to zero,
Brnzp ExitProg ; exits program when "X" is entered.
    InputVal .FILL x3501
    CheckValA LEA R2, InputVal
    JSR ToLowerCase
    ADD R2, R2, #1 ; R2 moves to next location.
    BRnzp UpperEncryptBound
    CheckValB JSR ToLowerCase
    ADD R2, R2, #1 ; R2 moves to next location.
    BRnzp UpperDecryptBound
    CheckValC JSR ToLowerCase
    AND R2, R2, #0 ; Used to handle malicious input.
    JSR ASCIIRange ; restricts boundaries of the encryption key.
    AND R2, R2, #0

UserInput AND R0, R0, #0 ; clears R0. 
    AND R1,R1, #0 ; clears R1.
    AND R2, R2, #0; clears R2.
    AND R3, R3, #0; clears R3.
    AND R4, R4, #0; clears R4.
TxtMsg .STRINGZ "input 16 chars then press <Enter>"
  LEA R0, MenuMessage
   TRAP x22
    TRAP x23
    StoreVal .FILL x3500
    ST R0, StoreVal ; stores R0 for use later.
    LEA R2, InputVal ; R2 is used for a later function.
    BRnzp DecideOp
;---------------------------------------------------------------------------------------------------------------------------
    EInput AND R0, R0, #0 ; clears R0. 
        AND R1, R1, #0 ; clears R1.
ADD R1, R1, #14 ;a string of the correct length of characters.
        ADD R1, R1, #3 ; add last characters.
        Count .FILL x3508
        AND R2, R2, #0 ;clears R2, store memory address at this location.
        LEA R2, MESSAGE
        LEA R0, TxtMsg
        TRAP x22
        Loop TRAP x20 ; obtain input.
            ADD R1, R1, #-1 ; decrement value of R1.
            BRn GetLength
            AND R3, R3, #0 ; clears R3 in order to test for a carriage return
            STR R0, R2, #0
            ADD R2, R2, #1
            LD R3, LastChar
            ADD R3, R3, R0 ; last character is reached if the value is zero.
            BRz GetLength
            BRnp Loop
;-----------------------------------------------------------------------------------------------------------------------------------------
   GetKey  GetKeyLocation .FILL x3509
        LEA R6, GetKey
        LEA R0,EncryptString
        AND R3, R3, #0
        LEA R3, CheckValD
        JMP R0 ; keeps track of memory.
        CheckValD AND R1, R1, #0 ;
        ADD R1, R0, #-1 ; decrement value.
        BRn InvalidString
        BRz memoryHold
        BRp clearVal
        InvalidString Invalid_Input .STRINGZ "Invalid entry"
            LEA R0, Invalid_Input
            TRAP x22
            JMP R6
        memoryHold AND R2, R2, #0 ; R2 holds memory location
            LD R2, GetKeyLocation
            STR R0, R2, #0
            LEA R6, UserInput
            LEA R0, EncryptionOp
            JMP R0
        clearVal AND R1, R1, #0
            RangeofValues .FILL x3507
            LD R1, RangeofValues
            NOT R1, R1
            ADD R1, R1, #1
            ADD R1, R0, R1
            BRnz memhold
            BRp MalInput
        memhold AND R2, R2, #0 ; R2 holds memory location again.
            LEA R2, GetKeyLocation
            STR R0, R2, #0
            LEA R6, UserInput
            LEA R0, EncryptionOp
            JMP R0
        MalInput LEA R0, Invalid_Input
            TRAP x22
            BRnzp GetKey
;----------------------------------------------------------------------------------------------------------------------------------------
    ENCRYPTIONOP AND R0, R0, #0 ; Clear R0, R2, and R4 again.
        AND R2, R2, #0
        AND R4, R4, #0
        LEA R4, MESSAGE ; R4 contains current character.
        ADD R4, R4, #-1 ; decrement value.
ADD R2, R2, #14
        ADD R2, R2, #3 ; iterates through every letter.
        ST R2, Count
        ELoop ADD R4, R4, #1 ; contains current address of the character.
            LD R2, Count
            ADD R2, R2, #-1 ;decrements the counter
            BRz placeholder ; if zero, process is complete.
            placeholder JMP R6
            ST R2, Count ; final value of R2 stored for later use.
            AND R0, R0, #0 ; clears register to hold final value.
            LDR R0, R4, #0 ; 
            ExclusiveOr AND R1, R1, #0 ; clear R1, value of B.
                ADD R1, R1, #1 ;
                AND R3, R3, #0 ; clear R3, value of B.
                NOT R3, R1 ; One's Complement.
                AND R3, R3, R0 ; XOR of A and !B.
                NOT R3, R3 ; NOT XOR of A and !B.
                NOT R2, R0 ; One's Complement of A.
                AND R2, R2, R1 ; XOR of B and !A.
                NOT R2, R2 ; NOT XOR of B and !A.
                AND R3, R3, R2 ; AND the two resulting NOT lines above.
                NOT R3, R3 ; Negates the previous line.
            Modulo AND R1, R1, #0 ; clears to prepare for R1 modulo subroutine
                AND R2, R2, #0
                LD R1, RangeofValues
                ADD R1, R1, #1 ; give mod a restrictive set of values (0-127).
                AND R0, R0, #0 ; XOR of A and B in R0.
                ADD R0, R0, R3 ; XOR of the current character.
                LD R3, GetKeyLocation ; R3 represents key of encryption.
                ADD R0, R3, R0
                ST R4, saveMod	; store values in this subroutine.
                NOT R4, R1	; One's Complement.
                ADD R4, R4, #1	; Adding one to make 2's complement.
                loop	ADD R0, R0,R4	; computes the difference of R0-R1.
                BRp loop	;if remainder exceeds R1, continue looping.
                BRz zerorem	; a zero remainder results in an exit.
                ADD R0, R1, R0	; a negative remainder, then add R0.
                zerorem	ADD R2, R0, #0	; copy R0 into R2, the result is returned in R2
                LD R4, saveMod	; current character memory location.
                STR R2, R4, #0
                BRnzp ELoop
;----------------------------------------------------------------------------------------------------------------------------------------
DecryptOp AND R0, R0, #0 ;  clearing R0, R1, R2, R3, R4 in case encryption was done beforehand.
    AND R1, R1, #0
    AND R2, R2, #0
    AND R3, R3, #0
    AND R4, R4, #0
    LEA R6, DecryptOp
    LD R0, GetKeyLocation
    ADD R0, R0, #0 ; A result of zero means no encryption, so error.
    BRnp Continue
    LEA R0, DecryptMsg
    TRAP x22
    BRnzp UserInput

LastChar .FILL #-13 ; the negative version of the carriage return value
;-------------------------------------------------------------------------------------------------------------------------------------
    DecideOp ADD R1, R1, #0
        BRnzp ExitUpperBound
        ExitUpperBound LDR R0, R2, #0 ; R0 represents first index of array.
            ADD R2, R2, #1
            AND R1, R1, #0 ; clears R1 to allow for value storage.
            LD R1, StoreVal
            ADD R1, R1, R0 ; compare R1 and R0.
            BRnp ExitLowerBound
            TRAP x25

    ExitLowerBound  LDR R0, R2, #0 ; R0 holds next index position of array.
        ADD R2, R2, #1
        AND R1, R1, #0 ; clears R1 for value storage.
        LD R1, StoreVal
        ADD R1, R1, R0 ; compare R1 and R0.
        BRnp EncryptUpperBound
        TRAP x25

    EncryptUpperBound  LDR R0, R2, #0 ; R0 holds next index position of the array.
        ADD R2, R2, #1
        AND R1, R1, #0 ; clears R1 for value storage.
        LD R1, StoreVal
        ADD R1, R1, R0 ; compare R1 and R0.
        BRz EInput
        BRnp EncryptLowerBound

    EncryptLowerBound LDR R0, R2, #0 ; R0 holds next index value of the array.
        ADD R2, R2, #1
        AND R1, R1, #0 ; clears R1 for value storage.
        LD R1, StoreVal
        ADD R1, R1, R0 ; Compare R1 and R0.
        BRz EInput
        Brnp DecryptUpperBound

    DecryptUpperBound LDR R0, R2, #0 ; R2 holds next index value of array.
        ADD R2, R2, #1
        AND R1, R1, #0 ; clears R1 for value storage.
        LD R1, StoreVal
        ADD R1, R1, R0 ; Compare R1 and R0.
        BRz DecryptOp
        BRnp DecryptLowerBound

    DecryptLowerBound LDR R0, R2, #0 ; R0 holds next index value of array.
        AND R1, R1, #0 ; clear R1 for value storage.
        LD R1, StoreVal
        ADD R1, R1, R0 ; Compare R1 and R0.
        BRz DecryptOp
        LEA R0, Invalid_Input
        TRAP x22
        BRnzp UserInput

    ExitProg AND R1, R1, #0 ; initializes R1 to zero.
        ADD R1, R1, #14 ;14
        ADD R1, R1, R1 ;28
        ADD R1, R1, #14 ;42
        ADD R1, R1, R1 ;84
        ADD R1, R1, #4
        NOT R1, R1 ; one's complement.
        ADD R1, R1, #1 ; two's complement.
        ST R1, InputVal
        BRnzp CheckValA

    UpperEncryptBound AND R1, R1, #0
        ADD R1, R1, #14 ;14
        ADD R1, R1, R1 ;28
        ADD R1, R1, R1 ;56
        ADD R1, R1, #13
        NOT R1, R1
        ADD R1, R1, #1
        STR R1, R2, #0
        BRnzp CheckValB

    UpperDecryptBound AND R1, R1, #0
        ADD R1, R1, #14 ;14
        ADD R1, R1, R1 ;28
        ADD R1, R1, R1 ;56
        ADD R1, R1, #12
        NOT R1, R1
        ADD R1, R1, #1
        STR R1, R2, #0
        BRnzp CheckValC

Continue LEA R3, CheckValE
    LEA R0, EncryptString
    JMP R0
    CheckValE LD R1, RangeofValues
    ADD R0, R0, #-2
    ST R0, GetKeyLocation
    NOT R1, R1
    ADD R1, R1, #1 ; two's complement.
    ADD R1, R1, R0
    BRp DecryptOp
    BRz Continue_On
    AND R1, R1, #0
    ADD R1, R0, #-1
    BRn DecryptOp

Continue_On LD R1, RangeofValues
    ADD R1, R1, #1
    NOT R0, R0
    ADD R0, R0, #1 ; two's complement.
    ADD R0, R1, R0
    ST R0, GetKeyLocation
    LEA R6, PrintMessageE
    BRnzp EncryptionOp
    getNext JMP R6
PrintMessageE LEA R4, MESSAGE
    AND R1, R1, #0
    ADD R1, R1, #14 ; stores counter information in R1.
    ADD R1, R1, #2
    PLoop LDR R0, R4, #0
        TRAP x21
        ADD R4, R4, #1 ; R4 R4 points to the next character.
        ADD R1, R1, #-1 ; decrease counter by 1 in R1.
        BRn getNext
        BRzp PLoop
;-------------------------------------------------------------------------------------------------------------------------------

GetLength ADD R1, R1, #0 ; initialize to zero.
    BRz GetKey
    MessageLine LEA R0, InvalidLength
    TRAP x22
    BRnzp EInput

    WeirdInput LEA R0, WeirdMessage
        TRAP x22
        BRnzp EInput

    ASCIIRange AND R3, R3, #0
        AND R2, R2, #0
        LEA R2, RangeofValues
        ADD R3, R3, #14 ;14
        ADD R3, R3, R3 ;28
        ADD R3, R3, R3 ;56
        ADD R3, R3, R3 ;112
        ADD R3, R3, #14 ;126
        ADD R3, R3, #1 ;127
        STR R3, R2, #0
        RET

MESSAGE .FILL x4000
.BLKW 15

EncryptString ReturnString .FILL X3524
    ST R3, ReturnString
    AND R3, R3, #0
    GetKeyLocationA .FILL x3520
    .BLKW 2
    LEA R0, EInput1
    TRAP x22

    LEA R4, GetKeyLocationA
    TLoop TRAP x20
        LEA R1, GetKeyLocationA
        ADD R1, R1, #2
        NOT R1, R1
        ADD R1, R1, #1 ; test if number exceeds value.
        ADD R1, R1, R4 ; a very large value.
        BRp InvalidString
        saveMod	.BLKW 1
        LD R1, LastChar
        ADD R1, R0, R1 ; a value of zero results in a carriage return.
        BRz AddEncrypt
        ADD R3, R3, #1 ; tracks number of digits.
        ADD R0, R0, #-14 ; convert from ASCII.
        ADD R0, R0, #-14
        ADD R0, R0, #-14
        ADD R0, R0, #-6
        STR R0, R4, #0 ;we store the number input at a specific location
        ADD R4, R4, #1 ; R4 points to the next location.
        BRnzp TLoop

;--------------------------------------------------------------------------------------------------------------------------------

EInput1 .STRINGZ "ENTER ENCRYPTION KEY (A NUMBER BETWEEN 1 AND 127). WHEN DONE PRESS <ENTER>"

DecryptMsg .STRINGZ "no text stored"

InvalidLength .STRINGZ "Input is not 16 chars long"

WeirdMessage .STRINGZ "Didn't enter a char"
.BLKW 5;allocating space to store value of every letter operation

AddEncrypt AND R1, R1, #0
    ADD R1, R3, #-2
    BRz TwoPlaces
    BRn OnePlace
    Original LEA R1, GetKeyLocationA
        ADD R1, R1, #1 ; points to second digit.
        AND R4, R4, #0 ; R4 is used as a counter.
        ADD R4, R4, #10
        AND R0, R0, #0
        LDR R1, R1, #0 ; R4 holds value of second digit.
        ADD R0, R0, R1 ; R0 holds the initial value of input.
        TimesTen ADD R0, R0, R1
            ADD R4, R4, #-1 ; decrements the counter by 1.
            BRz completeMult ;if the counter is zero go to next step.
            Brp TimesTen
        completeMult LEA R1, GetKeyLocationA
            ADD R1, R1, #1 ; points to the second digit.
            STR R0, R1, #0
            ADD R1, R1, #-1 ; points to the first digit.
            AND R4, R4, #0 ; clears R4, becomes a counter.
            ADD R4, R4, #14
            ADD R4, R4, #11 ;25
            ADD R4, R4, R4 ;50
            ADD R4, R4, R4 ;100
            AND R0, R0, #0
            LDR R1, R1, #0 ; R1 holds value of second digit.
            ADD R0, R0, R1 ; R0 holds initial input value.
        TimesHundred ADD R0, R0, R1
            ADD R4, R4, #-1 ; decrements the counter by 1 in R4.
            BRz Combine ; if the counter is zero, go to next step.
            Brp TimesHundred
        Combine LEA R1, GetKeyLocationA
            STR R0, R1, #0
            AND R4, R4, #0
            AND R1, R1, #0
            AND R0, R0, #0
            LD R1, GetKeyLocationA
            ADD R0, R0, R1
            LDR R1, R1, #1
            ADD R0, R0, R1
            LDR R1, R1, #1
            ADD R0, R0, R1
            LD R3, ReturnString
            JMP R3
    TwoPlaces LEA R1, GetKeyLocationA
        AND R4, R4, #0 ; clears R4, becomes a counter.
        ADD R4, R4, #10
        AND R0, R0, #0
        LDR R1, R1, #0 ; R1 holds the value of the second digit.
        ADD R0, R0, R1 ; R0 holds the initial input value.
        TimesTenTwo ADD R0, R0, R1
            ADD R4, R4, #-1 ; decrements the counter by 1 in R4.
            BRz product ; if the counter is zero, go to the next step.
            Brp TimesTenTwo
        product LEA R1, GetKeyLocationA
            LDR R1, R1, #1 ; points to the first digit.
            ADD R0, R0 ,R1
            LD R3, ReturnString
            JMP R3
    OnePlace LEA R1, GetKeyLocationA
        LDR R0, R1, #0 ; R0 contains single digit input.
        LD R3, ReturnString
        JMP R3


ToLowerCase AND R1, R1, #0
    ADD R1, R2, R1 ; an uppercase value is assigned a negative value. 
    ADD R2, R2, #1 ; R2 points to the next input operation.
    ADD R1, R1, #-1 ; conversion of number by magnitude.
    NOT R1, R1
    ADD R1, R1, #14
    ADD R1, R1, #14
    ADD R1, R1, #4
    NOT R1, R1
    ADD R1, R1, #1
    STR R1, R2, #0
    RET

.END

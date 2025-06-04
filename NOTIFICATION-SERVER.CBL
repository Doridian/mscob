        >>SOURCE FORMAT FREE
IDENTIFICATION DIVISION.
PROGRAM-ID. NOTIFICATION-SERVER.

DATA DIVISION.
WORKING-STORAGE SECTION.

01 NL PIC X VALUE x'0A'.

01 receive-buffer PIC X(65536).
01 receive-len BINARY-LONG UNSIGNED.

01 response-buffer PIC X(65536).

01 receive-command PIC X(64).
01 receive-txn PIC Z(3)9.
01 receive-trailer-idx BINARY-INT UNSIGNED.

01 receive-param PIC X(256).

01 msnp-version PIC Z(3)9 VALUE 9999.
01 cvr-version PIC Z(3)9 VALUE 9999.

01 connection-state BINARY-INT UNSIGNED.

01 CR PIC X(1) VALUE x'0D'.
01 LF PIC X(1) VALUE x'0A'.

*> Probably use CBL_GC_FORK to fork a listener for status updates after auth is completed
*> PostgreSQL LISTEN?

PROCEDURE DIVISION.
Main.
    MOVE 1 TO connection-state.
    PERFORM READ-COMMAND THRU READ-COMMAND-EXIT UNTIL connection-state = 0
    STOP RUN.

Read-Command.
    MOVE 1 TO receive-trailer-idx
    ACCEPT receive-buffer
    MOVE FUNCTION TRIM(receive-buffer) TO receive-buffer
    MOVE FUNCTION LENGTH(FUNCTION TRIM(receive-buffer TRAILING)) TO receive-len
    UNSTRING receive-buffer DELIMITED BY SPACE
        INTO receive-command, receive-txn
        WITH POINTER receive-trailer-idx
    END-UNSTRING

    MOVE FUNCTION UPPER-CASE(receive-command) TO receive-command
    MOVE SPACES TO response-buffer

    EVALUATE TRUE
        WHEN receive-command = "VER"
            PERFORM UNTIL receive-trailer-idx > receive-len
                UNSTRING receive-buffer DELIMITED BY SPACE
                    INTO receive-param
                    WITH POINTER receive-trailer-idx
                END-UNSTRING
                EVALUATE TRUE
                    WHEN receive-param(1:4) = "MSNP"
                        MOVE receive-param(5:) TO msnp-version
                    WHEN receive-param(1:3) = "CVR"
                        MOVE receive-param(4:) TO cvr-version
                END-EVALUATE
            END-PERFORM

            IF msnp-version = 9999 OR cvr-version = 9999
                MOVE "0" TO response-buffer
                GO TO READ-COMMAND-ERROR
            END-IF

            *> We can't support MSNP > 7 as it requires passport auth
            *> Which uses MSFT servers hardcoded in the client
            IF msnp-version > 7
                MOVE 7 TO msnp-version
            END-IF

            IF cvr-version > 0
                MOVE 0 TO cvr-version
            END-IF

            STRING
                "MSNP",
                FUNCTION TRIM(msnp-version),
                " CVR",
                FUNCTION TRIM(cvr-version)
                    DELIMITED BY SIZE
                INTO response-buffer
            END-STRING

        WHEN receive-command = "CVR"
            MOVE "1.0.0000 1.0.0000 1.0.0000 https://doridian.net https://doridian.net" TO response-buffer

        *> Error cases
        WHEN receive-command = SPACES
            GO TO READ-COMMAND-ERROR
        WHEN OTHER
            DISPLAY "Invalid command " FUNCTION TRIM(receive-command)
            GO TO READ-COMMAND-ERROR
    END-EVALUATE
    .

Read-Command-Exit.
    DISPLAY FUNCTION TRIM(receive-command) " " FUNCTION TRIM(receive-txn) " " FUNCTION TRIM(response-buffer) CR
    .

Read-Command-Error.
    MOVE 0 TO connection-state
    IF response-buffer NOT = SPACES
        GO TO READ-COMMAND-EXIT
    END-IF
    .

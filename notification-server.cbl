      $set sourceformat(free)
IDENTIFICATION DIVISION.
PROGRAM-ID. NOTIFICATION-SERVER.

DATA DIVISION.
WORKING-STORAGE SECTION.

01 C-ALL-CHARS.
   05 C-LOWER-ALPHA PIC X(26)
       VALUE "abcdefghijklmnopqrstuvwxyz".
   05 C-UPPER-ALPHA PIC X(26)
       VALUE "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
   05 C-NUMERIC PIC X(10)
       VALUE "0123456789".
   05 C-SPECIAL PIC X(8)
       VALUE "()[]{}!$".
01 C-CHARS-ARRAY REDEFINES C-ALL-CHARS.
   05 C-CHARS-INDEX OCCURS 70 TIMES PIC X.

01 CR_LF_NUL.
    05 CR PIC X(1) VALUE x'0D'.
    05 LF PIC X(1) VALUE x'0A'.
    05 NUL PIC X(1) VALUE x'00'.

01 receive-buffer PIC X(65536).
01 receive-buffer-array REDEFINES receive-buffer.
    05 receive-buffer-char OCCURS 65536 TIMES PIC X.
01 receive-len BINARY-LONG UNSIGNED.

01 response-buffer PIC X(65536).
01 response-buffer-array REDEFINES response-buffer.
    05 response-buffer-char OCCURS 65536 TIMES PIC X.
01 response-len BINARY-LONG UNSIGNED.

01 temp-ptr POINTER.
01 temp-int BINARY-INT.
01 temp-int-2 BINARY-INT.
*> 64 + 1" " + (3+1) + 1" " + 65536 + 3"\r\n\0" + 1 (margin)
01 output-buffer PIC X(65610).

01 receive-command PIC X(64).
01 receive-txn PIC Z(3)9.
01 receive-trailer-idx BINARY-INT UNSIGNED.

01 receive-param PIC X(256).
01 receive-param-2 PIC X(256).

01 msnp-version PIC Z(3)9 VALUE 9999.
01 cvr-version PIC Z(3)9 VALUE 9999.

01 connection-state BINARY-INT UNSIGNED.
*> 0 = closed, 1 = need-ver, 2 = need-cvr, 3 = in-auth, 4 = authed/ready

01 user-challenge PIC X(16).
01 user-challenge-array REDEFINES user-challenge.
   05 user-challenge-char OCCURS 16 TIMES PIC X.
01 user-handle PIC X(256).
01 user-nickname PIC X(256).
01 user-password PIC X(256).
01 security-package PIC X(256).

01 stdin POINTER.
01 stdout POINTER.
01 stderr POINTER.

*> Probably use CBL_GC_FORK to fork a listener for status updates after auth is completed
*> PostgreSQL LISTEN?

PROCEDURE DIVISION.
    CALL 'get_file' USING
        BY VALUE 0
        GIVING stdin
    END-CALL
    CALL 'get_file' USING
        BY VALUE 1
        GIVING stdout
    END-CALL
    CALL 'get_file' USING
        BY VALUE 2
        GIVING stderr
    END-CALL

    MOVE 1 TO connection-state
    PERFORM READ-COMMAND THRU READ-COMMAND-RETURN UNTIL connection-state = 0
    STOP RUN
    .

Read-Command.
    MOVE 1 TO receive-trailer-idx

    CALL 'fgets' USING
        BY REFERENCE receive-buffer
        BY VALUE 65535 *> One less on purpose!
        BY VALUE stdin
        GIVING temp-ptr
    END-CALL

    IF temp-ptr = NULL
        GO TO READ-COMMAND-ERROR
    END-IF

    MOVE 0 TO receive-len
    INSPECT receive-buffer TALLYING receive-len FOR CHARACTERS BEFORE INITIAL NUL

    PERFORM WITH TEST BEFORE UNTIL
            receive-len < 1 OR (
                receive-buffer-char(receive-len) NOT = CR AND
                receive-buffer-char(receive-len) NOT = LF AND
                receive-buffer-char(receive-len) NOT = " "
            )
        SUBTRACT 1 FROM receive-len
    END-PERFORM

    IF receive-len < 1 THEN
        GO TO READ-COMMAND-RETURN
    END-IF

    MOVE SPACES TO receive-buffer(receive-len + 1:)

    UNSTRING receive-buffer DELIMITED BY SPACE
        INTO
            receive-command,
            receive-txn
        WITH POINTER receive-trailer-idx
    END-UNSTRING

    MOVE SPACES TO response-buffer

    EVALUATE receive-command ALSO connection-state
        WHEN "VER" ALSO 1
            *> VER 0 MSNP8 CVR5
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
            IF FUNCTION NUMVAL(msnp-version) > 7
                MOVE 7 TO msnp-version
            END-IF

            IF FUNCTION NUMVAL(cvr-version) > 0
                MOVE 0 TO cvr-version
            END-IF

            STRING
                "MSNP" FUNCTION TRIM(msnp-version)
                " CVR" FUNCTION TRIM(cvr-version)
                    DELIMITED BY SIZE
                INTO response-buffer
            END-STRING

            MOVE 2 TO connection-state

        WHEN "CVR" ALSO 2
            MOVE "1.0.0000 1.0.0000 1.0.0000 https://doridian.net https://doridian.net" TO response-buffer

            MOVE 3 TO connection-state

        WHEN "USR" ALSO 3
            UNSTRING receive-buffer DELIMITED BY SPACE
                INTO receive-param, receive-param-2
                WITH POINTER receive-trailer-idx
            END-UNSTRING

            EVALUATE receive-param-2(1:1)
                WHEN "I"
                    EVALUATE receive-param
                        WHEN "MD5"
                            MOVE receive-param-2(2:) TO user-handle
                            IF FUNCTION TRIM(user-handle) = SPACES
                                MOVE "Empty user handle in USR command" TO response-buffer
                                MOVE "200" TO receive-command
                                GO TO READ-COMMAND-ERROR
                            END-IF

                            *> TODO: Load actual password and nickname
                            MOVE user-handle TO user-nickname
                            MOVE "test" TO user-password
                            PERFORM VARYING temp-int-2 FROM 1 BY 1
                                    UNTIL temp-int-2 > 16
                                COMPUTE temp-int = (FUNCTION RANDOM * 69) + 1
                                MOVE C-CHARS-INDEX(temp-int) TO user-challenge-char(temp-int-2)
                            END-PERFORM
                        WHEN OTHER
                            STRING
                                "Unsupported security package '"
                                FUNCTION TRIM(receive-param)
                                "' in USR I command"
                                    DELIMITED BY SIZE
                                INTO response-buffer
                            END-STRING
                            MOVE "200" TO receive-command
                            GO TO READ-COMMAND-ERROR
                    END-EVALUATE

                    MOVE receive-param TO security-package
                    STRING
                        security-package DELIMITED BY SPACE
                        " S" DELIMITED BY SIZE
                        user-challenge DELIMITED BY SPACE
                        INTO response-buffer
                    END-STRING

                WHEN "S"
                    IF security-package = SPACES
                        MOVE "Expected USR I before USR S" TO response-buffer
                        MOVE "200" TO receive-command
                        GO TO READ-COMMAND-ERROR
                    END-IF

                    IF receive-param NOT = security-package
                        STRING
                            "Expected security package '"
                            FUNCTION TRIM(security-package)
                            "' in USR S command"
                                DELIMITED BY SIZE
                            INTO response-buffer
                        END-STRING
                        MOVE "200" TO receive-command
                        GO TO READ-COMMAND-ERROR
                    END-IF

                    EVALUATE security-package
                        WHEN "MD5"
                            MOVE 1 TO temp-int
                            STRING
                                user-password
                                user-challenge
                                    DELIMITED BY SPACE
                                NUL DELIMITED BY SIZE
                                INTO output-buffer
                                WITH POINTER temp-int
                            END-STRING

                            SUBTRACT 2 FROM temp-int

                            CALL 'MD5' USING
                                BY REFERENCE output-buffer
                                BY VALUE temp-int
                                BY REFERENCE user-password
                            END-CALL

                            IF FUNCTION UPPER-CASE(receive-param-2(2:)) NOT =
                                    FUNCTION HEX-OF(user-password(1:16))
                                MOVE "Invalid password" TO response-buffer
                                MOVE "900" TO receive-command
                                GO TO READ-COMMAND-ERROR
                            END-IF

                            MOVE SPACES TO user-password
                            MOVE SPACES TO security-package

                            STRING
                                "OK " DELIMITED BY SIZE
                                user-handle DELIMITED BY SPACE
                                " " DELIMITED BY SIZE
                                user-nickname DELIMITED BY SPACE
                                INTO response-buffer
                            END-STRING
                            MOVE 4 TO connection-state
                        WHEN OTHER
                            STRING
                                "Unsupported security package '"
                                FUNCTION TRIM(receive-param)
                                "' in USR S command"
                                    DELIMITED BY SIZE
                                INTO response-buffer
                            END-STRING
                            MOVE "200" TO receive-command
                            GO TO READ-COMMAND-ERROR
                    END-EVALUATE

                    WHEN OTHER
                        MOVE "Unsupported USR command" TO response-buffer
                        MOVE "200" TO receive-command
                        GO TO READ-COMMAND-ERROR
            END-EVALUATE

        WHEN "TST" ALSO > 0
            CALL 'fread' USING
                BY REFERENCE response-buffer
                BY VALUE 1
                BY VALUE 16
                BY VALUE stdin
                GIVING response-len
            END-CALL

            MOVE SPACES TO response-buffer(response-len:)

            DISPLAY "Got " response-len " chars"
            GO TO READ-COMMAND-RETURN

        WHEN OTHER
            STRING
                "Invalid/unexpcted command '"
                FUNCTION TRIM(receive-command)
                "'"
                    DELIMITED BY SIZE
                INTO response-buffer
            END-STRING
            MOVE "200" TO receive-command
            GO TO READ-COMMAND-ERROR
    END-EVALUATE
    .

Read-Command-Respond.
    STRING
        FUNCTION TRIM(receive-command) " "
        FUNCTION TRIM(receive-txn) " "
        FUNCTION TRIM(response-buffer)
        CR_LF_NUL
           DELIMITED BY SIZE
        INTO output-buffer
    END-STRING

    CALL 'fputs' USING
        BY REFERENCE output-buffer
        BY VALUE stdout
        GIVING temp-int
    END-CALL

    IF temp-int < 0
        GO TO READ-COMMAND-ERROR
    END-IF
    .

Read-Command-Return.

Read-Command-Error.
    *>MOVE 0 TO connection-state
    IF response-buffer NOT = SPACES
        GO TO READ-COMMAND-RESPOND
    END-IF
    .

END PROGRAM NOTIFICATION-SERVER.

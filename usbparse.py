import json

# Extract key usb key sequence presses from json file extracted from Wireshark

map = {0x29: 'Esc',
     0x1E: "1",
     0x1F: "2",
     0x20: "3",
     0x21: "4",
     0x22: "5",
     0x23: "6",
     0x24: "7",
     0x25: "8",
     0x26: "9",
     0x27: "0",
     0x2D: "_ / -",
     0x2E: "+ / =",
     0x2A: "Back space",
     0x2B: "Tab",
     0x14: "Q",
     0x1A: "W",
     0x08: "E",
     0x15: "R",
     0x17: "T",
     0x1C: "Y",
     0x18: "U",
     0x0C: "I",
     0x12: "O",
     0x13: "P",
     0x2F: "{",
     0x30: "}",
     0x28: "Enter",
     0x58: "Enter KP",
     0xE0: "Ctrl L",
     0xE4: "Ctrl R",
     0x04: "A",
     0x16: "S",
     0x07: "D",
     0x09: "F",
     0x0A: "G",
     0x0B: "H",
     0x0D: "J",
     0x0E: "K",
     0x0F: "L",
     0x33: ":",
     0x34: "\"",
     0x35: "~",
     0xE1: "Shift L",
     0x31: "|",
     0x53: "(INT 2)",
     0x1D: "Z",
     0x1B: "X",
     0x06: "C",
     0x19: "V",
     0x05: "B",
     0x11: "N",
     0x10: "M",
     0x36: "<",
     0x37: ">",
     0x38: "?",
     0x54: "/",
     0xE5: "Shift R",
     0x2C: " "
     }

# From http://www.quadibloc.com/comp/scan.htm
# Scan Code               Key       Scan Code               Key         Scan Code               Key
#   Set    Set  Set  USB              Set    Set  Set  USB                Set    Set  Set  USB
#    1      2    3                     1      2    3                       1      2    3
#
#    01     76   08   29  Esc          37     7C            * PrtSc     E0 5E  E0 37            Power
#    02     16   16   1E  ! 1          37+    7C+  7E   55  * KP        E0 5F  E0 3F            Sleep
#    03     1E   1E   1F  @ 2       37/54+ 7C/84   57   46  PrtSc       E0 63  E0 5E            Wake
#    04     26   26   20  # 3          38     11   19   E2  Alt L       E0 20  E0 23        7F  Mute
#    05     25   25   21  $ 4       E0 38  E0 11   39   E6  Alt R       E0 30  E0 33        80  Volume Up
#    06     2E   2E   22  % 5          39     29   29   2C  Space       E0 2E  E0 21        81  Volume Down
#    07     36   36   23  ^ 6          3A     58   14   39  Caps Lock   E0 17  E0 43        7B  Cut
#    08     3D   3D   24  & 7          3B     05   07   3A  F1          E0 18  E0 44        7C  Copy
#    09     3E   3E   25  * 8          3C     06   0F   3B  F2          E0 0A  E0 46        7D  Paste
#    0A     46   46   26  ( 9          3D     04   17   3C  F3          E0 3B  E0 05        75  Help
#    0B     45   45   27  ) 0          3E     0C   1F   3D  F4          E0 08  E0 3D        7A  Undo
#    0C     4E   4E   2D  _ -          3F     03   27   3E  F5          E0 07  E0 36            Redo
#    0D     55   55   2E  + =          40     0B   2F   3F  F6          E0 22  E0 34            Play
#    0E     66   66   2A  Back Space   41     83   37   40  F7          E0 24  E0 3B            Stop
#    0F     0D   0D   2B  Tab          42     0A   3F   41  F8          E0 10  E0 15            Skip Back
#    10     15   15   14  Q            43     01   47   42  F9          E0 19  E0 4D            Skip Fwd
#    11     1D   1D   1A  W            44     09   4F   43  F10         E0 2C  E0 1A            Eject
#    12     24   24   08  E            45+    77+  76   53  Num Lock    E0 1E  E0 1C            Mail
#    13     2D   2D   15  R         45/46+ 77/7E+  62   48  Pause/Bk    E0 32  E0 3A            Web
#    14     2C   2C   17  T            46     7E            ScrLk/Bk    E0 3C  E0 06            Music
#    15     35   35   1C  Y            46+    7E+  5F   47  Scroll Lock E0 64  E0 08            Pictures
#    16     3C   3C   18  U            47     6C   6C   5F  7 Home KP   E0 6D  E0 50            Video
#    17     43   43   0C  I         E0 47* E0 6C*  6E   4A  Home CP
#    18     44   44   12  O            48     75   75   60  8 Up KP        5B     1F   08   68  F13
#    19     4D   4D   13  P         E0 48* E0 75*  63   52  Up CP          5C     27   10   69  F14
#    1A     54   54   2F  { [          49     7D   7D   61  9 PgUp KP      5D     2F   18   6A  F15
#    1B     5B   5B   30  } ]       E0 49* E0 7D*  6F   4B  PgUp CP        63     5E   2C   6B  F16
#    1C     5A   5A   28  Enter        4A     7B   84   56  - KP           64     08   2B   6C  F17
# E0 1C  E0 5A   79   58  Enter KP     4B     6B   6B   5C  4 Left KP      65     10   30   6D  F18
#    1D     14   11   E0  Ctrl L    E0 4B* E0 6B*  61   50  Left CP        66     18   38   6E  F19
# E0 1D  E0 14   58   E4  Ctrl R       4C     73   73   97  5 KP           67     20   40   6F  F20
#    1E     1C   1C   04  A            4D     74   74   5E  6 Right KP     68     28   48   70  F21
#    1F     1B   1B   16  S         E0 4D* E0 74*  6A   4F  Right CP       69     30   50   71  F22
#    20     23   23   07  D            4E     79   7C   57  + KP           6A     38   57   72  F23
#    21     2B   2B   09  F            4F     69   69   59  1 End KP       6B     40   5F   73  F24
#    22     34   34   0A  G         E0 4F* E0 69*  65   4D  End CP                          75              Help
#    23     33   33   0B  H            50     72   72   5A  2 Down KP     [71]    19   05   9A  Attn  SysRq
#    24     3B   3B   0D  J         E0 50* E0 72*  60   51  Down CP        76     5F   06   9C  Clear
#    25     42   42   0E  K            51     7A   7A   5B  3 PgDn KP                       76              Stop
#    26     4B   4B   0F  L         E0 51* E0 7A*  6D   4E  PgDn CP                         77              Again
#    27     4C   4C   33  : ;          52     70   70   62  0 Ins KP       72     39   04   A3  CrSel       Properties
#    28     52   52   34  " '       E0 52* E0 70*  67   49  Ins CP                     0C       Pause ErInp
#    29     0E   0E   35  ~ `          53     71   71   63  . Del KP                        78              Undo
#    2A     12   12   E1  Shift L   E0 53* E0 71*  64   4C  Del CP         74     53   03   A4  ExSel SetUp
#    2B     5D   5C   31  | \          54     84            SysRq          6D     50   0E       ErEOF Recrd
#    2B     5D   53   53  (INT 2)      56     61   13   64  (INT 1)
#    2C     1A   1A   1D  Z            57     78   56   44  F11                             80              Copy
#    2D     22   22   1B  X            58     07   5E   45  F12                        83       Print Ident
#    2E     21   21   06  C         E0 5B  E0 1F   8B   E3  Win L          6F     6F   0A       Copy  Test
#    2F     2A   2A   19  V         E0 5C  E0 27   8C   E7  Win R
#    30     32   32   05  B         E0 5D  E0 2F   8D   65  WinMenu                         81              Paste
#    31     31   31   11  N            70     13   87   88  katakana       75     5C   01       Enl   Help
#    32     3A   3A   10  M            73     51   51   87  (INT 3)        6C     48   09       Ctrl
#    33     41   41   36  < ,          77     62        8C  furigana                        82              Find
#    34     49   49   37  > .          79     64   86   8A  kanji                           79              Cut
#    35     4A   4A   38  ? /          7B     67   85   8B  hiragana
#    35+    4A+  77   54  / KP         7D     6A   5D   89  (INT 4)     E0 4C  E0 73   62       Rule
#    36     59   59   E5  Shift R     [7E]    6D   7B       (INT 5)



def main():
    print("Hej " + map[0x22])
    jsonObj = json.loads(open("/tmp/foo.json", "r").read())

    print ("Size: " + str(len(jsonObj)))

    prevValue = -1
    outputStr = ""
    for obj in jsonObj:
        # print(">> " + str(obj.keys()))
        if 'usb.capdata' in obj['_source']['layers']:
            data = obj['_source']['layers']['usb.capdata']
            # print(">>> " + data)
            hexStr = "0x" + data.split(":")[2]
            hex = int(hexStr, 16)
            if prevValue != hex and hex != 0:
                print("= " + hexStr + " " + str(hex) + " \t" + (map[hex] if hex in map else "??"))
                prevValue = hex
                outputStr += (map[hex] if hex in map else "??")
            else:
                prevValue = -1

    print ("Output:")
    print (outputStr)



if __name__ == '__main__':
    main()

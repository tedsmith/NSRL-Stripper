unit uNSRLStripper;

{$mode objfpc}{$H+}
{$J+}  // Hex 1A (0x1A) is the CTRL-Z and DOS EOF char, and its behaviour is controlled by boolean CtrlZMarksEOF.
       // By setting {$J+} and then using CtrlZMarksEOF := False; we can ensure acceptance and not get confused
       // by old EOF marker values.
       // https://github.com/tedsmith/NSRL-Stripper/issues/2

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls;

type

  { TForm1 }

  TForm1 = class(TForm)
    btnSelectInputFile: TButton;
    cbIncludeHeader: TCheckBox;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    lblEndTime: TLabel;
    lblInputFile: TLabel;
    lblOutputFile: TLabel;
    lblProgress: TLabel;
    lblStartTime: TLabel;
    OpenDialog1: TOpenDialog;
    RadioGroup1: TRadioGroup;
    SaveDialog1: TSaveDialog;
    procedure btnSelectInputFileClick(Sender: TObject);
    function CheckSourceStructure(InputFile : string) : boolean;
    procedure FormCreate(Sender: TObject);
    function ProcessLine(s : string; Len : integer) : string;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;


implementation

{$R *.lfm}

{ TForm1 }

// Data is of the form :
{
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
"0000002D9D62AEBE1E0E9DB6C4C4C7C16A163D2C","1D6EBB5A789ABD108FF578263E1F40F3","FFFFFFFF","_sfx_0024._p",4109,21000,"358",""
So if SHA-1 selected, read line to first ',' and read backwards 40 chars.
If MD5 selected, read line to first ',' and read forwards 32.
}

procedure TForm1.btnSelectInputFileClick(Sender: TObject);
var
  FileIn : Textfile;
  FileOut : Textfile;
  LineRead, HashValue : string;
  HashAlg : string;
  LinesWritten : integer  = Default(integer);
  RefreshBuffer : integer = Default(integer);
  SourceIsOK : boolean = Default(Boolean);
  itterationcount : QWord = Default(QWord);
  StartTime, EndTime, TimeTaken : TDateTime;
  const
    RefreshBufferLimit : integer = 100000; // Every 100K lines, refresh interface

begin
  CtrlZMarksEOF := False;
  LinesWritten := 0;

  if OpenDialog1.Execute then
    begin
    case RadioGroup1.ItemIndex of
      0: begin
      HashAlg := 'SHA-1';
      end;
      1: begin
      HashAlg := 'MD5';
      end;
      2: begin
      HashAlg := 'CRC';
      end;
    end;

    try
      AssignFile(FileIn, OpenDialog1.FileName);
      reset(FileIn);
    finally
      lblInputFile.Caption := 'Input File: ' + OpenDialog1.FileName;
    end;

    if SaveDialog1.Execute then
    begin
      try
      AssignFile(FileOut, SaveDialog1.FileName);
      Rewrite(FileOut);
      if cbIncludeHeader.checked then Writeln(FileOut, HashAlg);
      inc(LinesWritten, 1);
      finally
      lblOutputFile.Caption := 'Output file : ' + SaveDialog1.Filename;
      end;
    end;

    // Check the sourcefile is structured as the programmer expected
    SourceIsOK := CheckSourceStructure(OpenDialog1.FileName);
    if SourceIsOK then
    begin
      // Source file is OK. Lets begin...
      StartTime := Now;
      lblStartTime.Caption:= 'Started at : ' + FormatDateTime('DD/MM/YY HH:MM:SS', StartTime);

      if HashAlg = 'SHA-1' then
      begin
        while not EOF(FileIn) do
        begin
        inc(itterationcount, 1);

          // This weird bit of code allows EOF, and ergo one line read, ready for the next line,
          // but it avoids the first line of the NSRL file (column headings) being written to the outputfile.
          // Because that would prevent X-Ways Forensics from importing the hash values.
          if LinesWritten = 1 then
          begin
            readln(FileIn, LineRead);
            HashValue := ProcessLine(LineRead, 40);
            // Notice no writeln here, to omit the column heading
            inc(LinesWritten, 1);
          end
          else
            begin
              readln(FileIn, LineRead);
              HashValue := ProcessLine(LineRead, 40);
              Writeln(FileOut, HashValue);
              inc(LinesWritten, 1);
              inc(RefreshBuffer, 1);
              // We don't want the interface refreshing millions of times!
              // So we refresh every Xth times, as specified by const RefreshBufferLimit
              if RefreshBuffer = RefreshBufferLimit then
              begin
                lblProgress.Caption:= IntToStr(LinesWritten) + ' lines ingested';
                Application.ProcessMessages;
                RefreshBuffer := 0;
              end;
            end;
        end;
      end;   // End of SHA-1

      if HashAlg = 'MD5' then
      begin
        while not EOF(FileIn) do
        begin
          if LinesWritten = 1 then
          begin
            readln(FileIn, LineRead);
            HashValue := ProcessLine(LineRead, 32);
            // Notice no writeln here, to omit the column heading
            inc(LinesWritten, 1);
          end
          else
            begin
              readln(FileIn, LineRead);
              HashValue := ProcessLine(LineRead, 32);
              Writeln(FileOut, HashValue);
              inc(LinesWritten, 1);
              inc(RefreshBuffer, 1);
              if RefreshBuffer = RefreshBufferLimit then
              begin
                lblProgress.Caption:= IntToStr(LinesWritten);
                Application.ProcessMessages;
                RefreshBuffer := 0;
              end;
            end;
        end;
      end;  // End of MD5

      if HashAlg = 'CRC' then
      begin
        while not EOF(FileIn) do
        begin
          if LinesWritten = 1 then
            begin
            readln(FileIn, LineRead);
            HashValue := ProcessLine(LineRead, 8);
            // Notice no writeln here, to omit the column heading
            inc(LinesWritten, 1);
            end
          else
            begin
              readln(FileIn, LineRead);
              HashValue := ProcessLine(LineRead, 8);
              Writeln(FileOut, HashValue);
              inc(LinesWritten, 1);
              inc(RefreshBuffer, 1);
              if RefreshBuffer = RefreshBufferLimit then
                begin
                lblProgress.Caption:= IntToStr(LinesWritten);
                Application.ProcessMessages;
                RefreshBuffer := 0;
                end;
            end;
        end;
      end; // End of CRC

      try
        CloseFile(FileIn);
        CloseFile(FileOut);
      finally
        lblProgress.Caption:= IntToStr(LinesWritten -1) + ' values written. Finished';
        Application.ProcessMessages;
      end;

    EndTime := Now;
    TimeTaken := (EndTime - StartTime);
    lblEndTime.Caption:= 'Finished at : ' + FormatDateTime('DD/MM/YY HH:MM:SS', EndTime) + ' , time taken : ' + FormatDateTime('HH:MM:SS', TimeTaken);
    end // End of source file check
    else ShowMessage('Input file is not constructed as expected. Output would fail. Aborted.')
    end; // End of open source file
end;

function TForm1.CheckSourceStructure(InputFile : String) : boolean;
{
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
"0000002D9D62AEBE1E0E9DB6C4C4C7C16A163D2C","1D6EBB5A789ABD108FF578263E1F40F3","FFFFFFFF","_sfx_0024._p",4109,21000,"358",""
"00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,10146,"358",""

This is 16 quotation marks on line 1, 12 on line 2, and 12 on line 3
So look for 40 quotation marks.
}
var
  i, QuoteMark : integer;
  stringdata, LineI : string;
  FileIn : Textfile;
begin
  result := false;
  QuoteMark := 0;

   try
     AssignFile(FileIn, InputFile);
     reset(FileIn);
   finally
   end;

  // Read the first 3 lines of the source file
  for i := 0 to 2 do
  begin
    ReadLn(FileIn, LineI);
    // Add each of the 3 lines of the read to StringData
    StringData := StringData + LineI;
  end;

  for i := 0 to Length(StringData) do
  begin
    if StringData[i] = '"' then inc(QuoteMark, 1);
  end;
  CloseFile(FileIn);
  if QuoteMark = 40 then result := true;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Set default hash to SHA-1 which is most likely the one folk need
  RadioGroup1.ItemIndex := 0;    // 0 is SHA-1 default
  // RadioGroup1.ItemIndex := 1; // 1 for Md5 default
  // RadioGroup1.ItemIndex := 2; // 2 for CRC default
end;

// Function ProcessLine : Takes the read line from the file (s) and then extracts
// the bytes from the releative position of the NSRL Text file.
// e.g. 40 bytes from string position 2 for SHA-1 (because pos 1 is a quotation char)
function TForm1.ProcessLine(s : string; Len : integer) : string;
var
  i : integer;
begin
  result := '';
  if Len = 40 then
  begin
    result := Copy(s, 2, 40);
  end;

  if Len = 32 then
    begin
      result := Copy(s, 45, 32);
    end;

  if Len = 8 then
    begin
      result := Copy(s, 80, 8);
    end;
end;

end.



$UtilitiesRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$definitionFilePath = Join-Path -Path $UtilitiesRoot -ChildPath "BowTieDefinition_PIAFServer.json"

$bowtieDefinition = Get-Content $definitionFilePath 
$bowtieObject = $bowtieDefinition | ConvertFrom-Json

$threats = $bowtieObject.Definition.Threats
$impacts = $bowtieObject.Definition.Impacts

# Defense/Mitigation box height
$dmHeight = 60

# Initialize SVG doc
$svgDoc = @"
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xml:space="preserve" width="1750" height="800" viewBox="0 0 1750 800" preserveAspectRatio="xMinYMin meet">
  <defs>
    <style type="text/css"><![CDATA[
      text {
        font-family: Segoe UI Light;
        font-weight: bold;
        font-size: 12px;
        text-anchor: middle;
      }
      text.title {
        font-size: 24px;
      }
      text.title2 {
        font-size: 18px;
      }
      text.link {
        text-decoration: underline;
        fill: blue;
      }
      line {
        stroke: #000000;
        stroke-width: 3px;
      }
      rect {
        stroke: #000000;
        stroke-width: 1px;
        fill: #FFFFFF;
      }
      rect.threat {
        stroke-width: 5px;
        stroke: #2B52FF;
      }
      rect.impact {
        stroke-width: 5px;
        stroke: #AA2020;
      }
      rect.pass {
        fill: #45f442;  /* green */
      }
      rect.low {
        fill: #fff428;  /* yellow */
      }
      rect.moderate {
        fill: #ffb028;  /* orange */
      }
      rect.severe {
        fill: #ff282f;  /* red */
      }
      rect.na {
        fill: #93938f;  /* gray */
      }
    ]]></style>
  </defs>
  
  <!-- Available substitutions: enclose in '%' to replace -->
  <!-- Title       : Replaced with file title -->
  <!-- Timestamp   : Replaced with report timestamp -->
  <!-- MachineName : Replaced with machine name -->
  <!-- AUxxxxx     : replaced with class name of Audit Item severity -->
  
  <!-- Title Lines -->
  <title>%Title%</title>
  <text x="20" y="25" class="title" style="text-anchor:start;">%Title%
    <tspan dx="10">—</tspan>
    <tspan dx="10">%MachineName%</tspan>
  </text>
  <text x="20" y="50" class="title2" style="text-anchor:start;">%Timestamp%</text>

"@

# Super hard to follow function to wrap words within the given $width
# Returns y coordinates to be used for the lines, based on the upperY
# and lowerY values. Note the upperY is the smaller value (SVG coords).
function SplitText($text, $width, $upperY, $lowerY, $scale=1)
# Approximately 6.34px per character at 12pt font
{
	if($text.Length -lt ($width / 6.34 / $scale))
	{
		$middle = $upperY + ($lowerY - $upperY)/2
		$props = @{'text'=$text; 'y'=($middle+5)}
		return New-Object PSCustomObject -Property $props
	}
	else
	{
		$splitText = $text -split ' '
		$i=0
		$workingStr = ''
		$lineSplitStrs = @()
		foreach($str in $splitText)
		{
			$workingStr += $str
			if($workingStr.Length -gt ($width / 6.34 / $scale))
			{
				$lineSplitStrs += $workingStr.SubString(0, ($workingStr.Length - $str.Length)).TrimEnd()
				$workingStr = $str + ' '
			}
			else { $workingStr += ' '}
		}
		$lineSplitStrs += $workingStr.TrimEnd()
		$lineSplitStrs = $lineSplitStrs | Where-Object { $_ -NE '' }
		$middle = $upperY + ($lowerY - $upperY)/2
		$topLine = $middle - 20*($lineSplitStrs.Count/2) + 15
		$y = $topLine
		$ret = @()
		foreach($splitStr in $lineSplitStrs)
		{
			$props = @{'text'=$splitStr; 'y'=($y)}
			$ret += New-Object PSCustomObject -Property $props
			$y += 20
		}
		return $ret
	}
}

$initialX = 20
$initialY = 70

# Find Centerline, to hold middle circle
if($threats.Count -ge $impacts.Count ) { $fewer = $impacts.Count } else { $fewer = $threats.Count }
$circleY = $initialY + 120*($fewer/2) - 10

# Longest threat branch sets width of left side
$maxThreats = 0
foreach($threat in $threats) {
	if($threat.Defenses.Count -gt $maxThreats) { $maxThreats = $threat.Defenses.Count }
}

# Draw the left side of the bow tie
$y = $initialY + 50
$linesMeetX = $initialX + 180 + 120*$maxThreats
foreach($threat in $threats)
{
	$x = $initialX + 120*($maxThreats - $threat.Defenses.Count)
	
	# Lines first
	$svgDoc += "`t<line x1=`"$x`" y1=`"$y`" x2=`"$($x+100+120*$threat.Defenses.Count)`" y2=`"$y`"/>`r`n"
	$svgDoc += "`t<line x1=`"$($x+100+120*$threat.Defenses.Count)`" y1=`"$y`" x2=`"$linesMeetX`" y2=`"$circleY`"/>`r`n"
	# Draw Branch name
	$y -= 50
	$svgDoc += "`t<rect x=`"$x`" y=`"$y`" width=`"100`" height=`"100`" class=`"threat`"/>`r`n"
	$splitText = SplitText $threat.Name 100 $y ($y+100)
	foreach($line in $splitText)
	{
		$svgDoc += "`t<text x=`"$($x+50)`" y=`"$($line.y)`">$($line.text)</text>`r`n"
	}
	# Draw defenses
	$y += (50 - $dmHeight/2)
	foreach($defense in $threat.Defenses)
	{
		$x += 120
		$svgDoc += "`t<rect x=`"$x`" y=`"$y`" width=`"100`" height=`"$dmHeight`""
		if($defense.AuditID) { $svgDoc += " class=`"%$($defense.AuditID)%`"" }
		$svgDoc += "/>`r`n"
		$splitText = SplitText $defense.Name 100 $y ($y+$dmHeight)
		foreach($line in $splitText)
		{
			$svgDoc += "`t<text x=`"$($x+50)`" y=`"$($line.y)`">$($line.text)</text>`r`n"
		}
	}

	# Move down to next branch Y
	$y += (120 + $dmHeight/2)
} # End Left half

# Draw the circle and middle rectangle
$x = $linesMeetX + 75
$svgDoc += "`t<line x1=`"$x`" y1=`"$circleY`" x2=`"$x`" y2=`"$($circleY-160)`" style=`"stroke-width: 5px;`"/>`r`n"
$svgDoc += "`t<circle cx=`"$x`" cy=`"$circleY`" r=`"75`" fill=`"#F47D42`" stroke=`"#000000`" stroke-width=`"5px`"/>`r`n"
foreach($line in (SplitText $bowtieObject.Circle 150 ($circleY-75) ($circleY+75) 1.5))
{
	$svgDoc += "`t<text x=`"$x`" y=`"$($line.y)`" class=`"title2`">$($line.text)</text>`r`n"
}
$svgDoc += "`t<rect x=`"$($x-85)`" y=`"$($circleY-185)`" width=`"170`" height=`"75`" style=`"stroke-width:5px;`"/>`r`n"
foreach($line in (SplitText $bowtieObject.Rectangle 170 ($circleY-185) ($circleY-110) 1.5))
{
	$svgDoc += "`t<text x=`"$x`" y=`"$($line.y)`" class=`"title2`">$($line.text)</text>`r`n"
}


<#
<line x1="875" y1="360" x2="875" y2="200" style="stroke-width: 5px;"/>
  <circle cx="875" cy="360" r="75" fill="#F47D42" stroke="#000000" stroke-width="5px"/>
  <text x="875" y="360" class="title2">PI Data Archive</text>
  <text x="875" y="380" class="title2">Compromise</text>
  <rect x="790" y="175" width="170" height="75" style="stroke-width:5px;"/>
  <text x="875" y="210" class="title2">PI Data Archive</text>
  <text x="875" y="230" class="title2">Server</text>
  #>

# Draw the right half of the bow tie
$rightHalfX = $x + 155
$linesMeetX = $x + 75
$y = $initialY + 50
foreach($impact in $impacts)
{
	$x = $rightHalfX

	# Lines first
	$svgDoc += "`t<line x1=`"$x`" y1=`"$y`" x2=`"$($x+100+120*$impact.Mitigations.Count)`" y2=`"$y`"/>`r`n"
	$svgDoc += "`t<line x1=`"$linesMeetX`" y1=`"$circleY`" x2=`"$rightHalfX`" y2=`"$y`"/>`r`n"

	# Draw mitigations
	$y -= ($dmHeight/2)
	foreach($mitigation in $impact.Mitigations)
	{
		$svgDoc += "`t<rect x=`"$x`" y=`"$y`" width=`"100`" height=`"$dmHeight`""
		if($mitigation.AuditID) { $svgDoc += " class=`"%$($mitigation.AuditID)%`"" }
		$svgDoc += "/>`r`n"
		$splitText = SplitText $mitigation.Name 100 $y ($y+$dmHeight)
		foreach($line in $splitText)
		{
			$svgDoc += "`t<text x=`"$($x+50)`" y=`"$($line.y)`">$($line.text)</text>`r`n"
		}
		$x += 120
	}

	# Draw impact name
	$y -= (50 - $dmHeight/2)
	$svgDoc += "`t<rect x=`"$x`" y=`"$y`" width=`"100`" height=`"100`" class=`"impact`"/>`r`n"
	$splitText = SplitText $impact.Name 100 $y ($y+100)
	foreach($line in $splitText)
	{
		$svgDoc += "`t<text x=`"$($x+50)`" y=`"$($line.y)`">$($line.text)</text>`r`n"
	}

	# Move down to next branch Y
	$y += 170
} # End right half

$maxImpacts = 0
foreach($impact in $impacts) {
	if($impact.Mitigations.Count -gt $maxImpacts) { $maxImpacts = $impact.Mitigations.Count }
}
$maxX = $rightHalfX + 120 + 120*($maxImpacts)
$maxY = $y - 50

# Set ViewPort and ViewBox with maxX and maxY
$svgDoc = $svgDoc -replace '(svg version.*)width=\"\d+\"', ('$1width="{0}"' -f $maxX)
$svgDoc = $svgDoc -replace '(svg version.*)height=\"\d+\"', ('$1height="{0}"' -f $maxY)
$svgDoc = $svgDoc -replace '(svg version.*)viewBox=\".+?\"', ('$1viewBox="0 0 {0} {1}"' -f $maxX, $maxY)

$svgDoc += "</svg>"
$ExportRoot = Join-Path -Path (Split-Path -Path (Split-Path -Path $UtilitiesRoot -Parent) -Parent) -ChildPath 'Export'
$exportName = "BowTie_$($bowtieObject.Type -split ' ' -join '')"
$svgDoc | Out-File (Join-Path -Path $ExportRoot -ChildPath "$exportName.svg")
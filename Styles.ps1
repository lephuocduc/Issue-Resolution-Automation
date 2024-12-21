# Form Styles
$script:FormStyles = @{
    DefaultSize = New-Object System.Drawing.Size(500, 300)
    StartPosition = "CenterScreen"
    BackColor = [System.Drawing.Color]::White
}

# Button Styles
$script:ButtonStyles = @{
    DefaultPadding = @{
        Horizontal = 50
        Vertical = 20
    }
    Spacing = 10
    StartOffset = 20
    Font = New-Object System.Drawing.Font("Segoe UI", 9)
    BackColor = [System.Drawing.Color]::White
    ExitBackColor = [System.Drawing.Color]::LightCoral
}

# TextBox Styles
$script:TextBoxStyles = @{
    Width = 200
    Height = 30
    Font = New-Object System.Drawing.Font("Segoe UI", 9)
}

# Label Styles
$script:LabelStyles = @{
    Width = 200
    Height = 30
    Font = New-Object System.Drawing.Font("Segoe UI", 9)
}

# Common Functions
function Set-ButtonStyle {
    param($button, $text, $yOffset)
    
    $graphics = [System.Drawing.Graphics]::FromImage((New-Object System.Drawing.Bitmap 1,1))
    $textSize = $graphics.MeasureString($text, $ButtonStyles.Font)
    
    $button.Text = $text
    $button.Font = $ButtonStyles.Font
    $button.Size = New-Object System.Drawing.Size(
        ($textSize.Width + $ButtonStyles.DefaultPadding.Horizontal), 
        ($textSize.Height + $ButtonStyles.DefaultPadding.Vertical)
    )
    $button.Location = New-Object System.Drawing.Point($ButtonStyles.StartOffset, $yOffset)
    $button.BackColor = $ButtonStyles.BackColor
    
    return $button
}

function Set-FormStyle {
    param($form)
    $form.Size = $FormStyles.DefaultSize
    $form.StartPosition = $FormStyles.StartPosition
    $form.BackColor = $FormStyles.BackColor
    return $form
}
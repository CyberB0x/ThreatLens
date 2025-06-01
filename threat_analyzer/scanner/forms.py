from django import forms

class SubmissionForm(forms.Form):
    url = forms.URLField(
        required=False,
        label="URL",
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите ссылку'
        })
    )
    file = forms.FileField(
        required=False,
        label="Файл",
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control'
        })
    )

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("url") and not cleaned.get("file"):
            raise forms.ValidationError("Нужно указать URL или загрузить файл.")
        return cleaned

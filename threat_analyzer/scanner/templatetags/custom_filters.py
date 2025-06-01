from django import template

register = template.Library()

@register.filter
def typeof(value):
    return type(value).__name__

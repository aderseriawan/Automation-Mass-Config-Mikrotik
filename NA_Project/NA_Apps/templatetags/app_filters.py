from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """
    Template filter to access dictionary items by key
    Usage: {{ my_dict|get_item:key_name }}
    """
    return dictionary.get(key, "")

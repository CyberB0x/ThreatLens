from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.submit_view, name="submit"),
    path("results/", views.results_view, name="results"),
    path("clear/", views.clear_results, name="clear_results"),
]


from . import views
from django.urls import path
urlpatterns = [
    path('', views.index,name="index"),
    path('wishlist/',views.wishlist,name="wishlist"),
    path('product/',views.product,name="product"),
    path('audiobook/',views.audiobook,name="audiobook"),
    #path('invoice/',views.GeneratePdf.as_view)
]
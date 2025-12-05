from django.urls import path
from .views import RegisterView, LoginView, LogoutView, ProfileView, PasswordChangeView, AdminPanelView, ManagerView, StaffView, PublicView

urlpatterns = [
    path('auth/register/', RegisterView.as_view()),
    path('auth/login/', LoginView.as_view()),
    path('auth/logout/', LogoutView.as_view()),
    path('auth/profile/', ProfileView.as_view()),
    path('auth/change-password/', PasswordChangeView.as_view()),

    path('admin-panel/', AdminPanelView.as_view()),
    path('management/', ManagerView.as_view()),
    path('staff-zone/', StaffView.as_view()),
    path('public/', PublicView.as_view())
]

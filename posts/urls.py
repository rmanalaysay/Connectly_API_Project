from django.urls import path
from .views import (
    UserListCreate,
    UserRegistrationView,
    UserLoginView,
    UserLogoutView,
    UserListView,
    PostListCreate,
    PostDetailView,
    CommentListCreate,
    ProtectedView,
    AdminOnlyView
)

urlpatterns = [
    # User endpoints
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('users/list/', UserListView.as_view(), name='user-list'),
    path('register/', UserRegistrationView.as_view(), name='user-register'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    
    # Post endpoints
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),
    
    # Comment endpoints
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    
    # Protected/Testing endpoints
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin-only'),
]

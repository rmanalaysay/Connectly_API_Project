from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Post, Comment
from .serializers import (
    UserSerializer, 
    UserRegistrationSerializer,
    PostSerializer, 
    CommentSerializer
)
from .permissions import IsPostAuthor, IsCommentAuthor


# Step 2: User Registration with Password Encryption
class UserRegistrationView(APIView):
    """
    View for user registration with automatic password hashing
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Create authentication token for the new user
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'user': UserSerializer(user).data,
                'token': token.key,
                'message': 'User registered successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Step 2: User Login with Password Verification
class UserLoginView(APIView):
    """
    View for user login with password verification
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response(
                {'error': 'Please provide both username and password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Step 2: Use authenticate method to validate credentials
        user = authenticate(username=username, password=password)
        
        if user is not None:
            # Authentication successful
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data,
                'message': 'Authentication successful!'
            }, status=status.HTTP_200_OK)
        else:
            # Invalid credentials
            return Response(
                {'error': 'Invalid credentials.'},
                status=status.HTTP_401_UNAUTHORIZED
            )


# Step 4: Protected endpoint - User Logout
class UserLogoutView(APIView):
    """
    View for user logout - deletes the authentication token
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Delete the user's token to logout
        request.user.auth_token.delete()
        return Response(
            {'message': 'Successfully logged out.'},
            status=status.HTTP_200_OK
        )


# Step 4: List all users (protected endpoint)
class UserListView(APIView):
    """
    View to list all users - requires authentication
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# Original UserListCreate - now split into separate views
class UserListCreate(APIView):
    permission_classes = [AllowAny]  # Allow anyone to view users or register
    
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        # Redirect to registration endpoint
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'user': UserSerializer(user).data,
                'token': token.key
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Step 3 & 4: PostListCreate with authentication and permissions
class PostListCreate(APIView):
    """
    View to list all posts or create a new post
    Requires authentication to create posts
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            # Automatically set the author to the authenticated user
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Step 3: PostDetail with role-based permissions (IsPostAuthor)
class PostDetailView(APIView):
    """
    View to retrieve, update, or delete a specific post
    Only the author can update or delete their post
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]
    
    def get_object(self, pk):
        try:
            post = Post.objects.get(pk=pk)
            # Check object-level permissions
            self.check_object_permissions(self.request, post)
            return post
        except Post.DoesNotExist:
            return None
    
    def get(self, request, pk):
        post = self.get_object(pk)
        if post is None:
            return Response(
                {'error': 'Post not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = PostSerializer(post)
        return Response(serializer.data)
    
    def put(self, request, pk):
        post = self.get_object(pk)
        if post is None:
            return Response(
                {'error': 'Post not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        post = self.get_object(pk)
        if post is None:
            return Response(
                {'error': 'Post not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        post.delete()
        return Response(
            {'message': 'Post deleted successfully'},
            status=status.HTTP_204_NO_CONTENT
        )


# Step 3 & 4: CommentListCreate with authentication
class CommentListCreate(APIView):
    """
    View to list all comments or create a new comment
    Requires authentication to create comments
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            # Automatically set the author to the authenticated user
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Step 4: Protected view example
class ProtectedView(APIView):
    """
    Example of a protected view that requires token authentication
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'message': 'Authenticated!',
            'user': request.user.username
        })


# Step 3: Admin-only view example
class AdminOnlyView(APIView):
    """
    Example of an admin-only view
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return Response({
            'message': 'Welcome, Admin!',
            'total_users': User.objects.count(),
            'total_posts': Post.objects.count(),
            'total_comments': Comment.objects.count()
        })

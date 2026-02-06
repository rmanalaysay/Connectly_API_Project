from rest_framework.permissions import BasePermission

# Step 3: Custom Permission - IsPostAuthor
class IsPostAuthor(BasePermission):
    """
    Custom permission to only allow authors of a post to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions are only allowed to the author of the post.
        return obj.author == request.user


class IsCommentAuthor(BasePermission):
    """
    Custom permission to only allow authors of a comment to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions are only allowed to the author of the comment.
        return obj.author == request.user


class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission to only allow admins to edit.
    Regular users can only read.
    """
    def has_permission(self, request, view):
        # Read permissions are allowed to any request
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions are only allowed to admin users
        return request.user and request.user.is_staff

from django.db import models
from django.contrib.auth.models import User

# Note: We're now using Django's built-in User model instead of a custom User model
# This provides built-in password hashing and authentication features

class Post(models.Model):
    content = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Post by {self.author.username} at {self.created_at}"
    
    class Meta:
        ordering = ['-created_at']  # Most recent posts first
    
    
class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"
    
    class Meta:
        ordering = ['-created_at']  # Most recent comments first

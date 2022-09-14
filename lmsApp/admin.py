from django.contrib import admin
from lmsApp.models import Category,Books,Students,Borrow

# Register your models here.
# admin.site.register(models.Groups)
class CategoryAdmin(admin.ModelAdmin):
      list_display    = ['name', 'description', 'status','date_added','date_created']
admin.site.register(Category,CategoryAdmin)

class BooksAdmin(admin.ModelAdmin):
      list_display    = ['category','isbn','title','description','publisher','date_published','status','date_added','date_created']
admin.site.register(Books,BooksAdmin)

class StudentsAdmin(admin.ModelAdmin):
      list_display    = ['code','first_name','last_name','gender','contact','email','address','status','date_added','date_created']
admin.site.register(Students,StudentsAdmin)

# class BorrowAdmin(admin.ModelAdmin):
#       list_display    = ['student','book','borrowing_date','return_date','status','date_added','date_created']
# admin.site.register(Borrow,BorrowAdmin)
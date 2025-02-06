from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Device, DeviceData

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'role', 'is_staff', 'is_active']
    list_filter = ['role', 'is_staff', 'is_active']
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Custom fields', {'fields': ('role',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'is_staff', 'is_active')}
        ),
    )

class DeviceAdmin(admin.ModelAdmin):
    list_display = ['name', 'type', 'status', 'customerid', 'created_at', 'updated_at']
    list_filter = ['type', 'status']
    search_fields = ['name', 'type']

class DeviceDataAdmin(admin.ModelAdmin):
    list_display = ['device', 'data_type', 'customerid', 'value', 'timestamp']
    list_filter = ['device', 'data_type']
    search_fields = ['data_type']

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super().get_search_results(request, queryset, search_term)
        
        if search_term:
            # Ensure that device__name works correctly
            matching_devices = Device.objects.filter(name__icontains=search_term)
            queryset |= self.model.objects.filter(device__in=matching_devices)

        return queryset, use_distinct

admin.site.register(User, CustomUserAdmin)
admin.site.register(Device, DeviceAdmin)
admin.site.register(DeviceData, DeviceDataAdmin)

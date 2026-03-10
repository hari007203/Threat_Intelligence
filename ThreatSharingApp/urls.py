from django.urls import path

from . import views

urlpatterns = [
			   path('', views.index, name="home"),
			   path("index.html", views.index, name="index"),
	       path('AdminLogin.html', views.AdminLogin, name="AdminLogin"), 
	       path('UserLogin.html', views.UserLogin, name="UserLogin"), 
	       path('AdminLoginAction', views.AdminLoginAction, name="AdminLoginAction"),	
	       path('UserLoginAction', views.UserLoginAction, name="UserLoginAction"),	
	       path('AddEmp.html', views.AddEmp, name="AddEmp"),
	       path('AddEmpAction', views.AddEmpAction, name="AddEmpAction"),	
	       path('ViewThreats', views.ViewThreats, name="ViewThreats"),
	       path('VisualizeThreat', views.VisualizeThreat, name="VisualizeThreat"),
	       path('AccessPages.html', views.AccessPages, name="AccessPages"),
	       path('AccessPagesAction', views.AccessPagesAction, name="AccessPagesAction"),
	       path('ViewShareThreat', views.ViewShareThreat, name="ViewShareThreat"),	      	
]

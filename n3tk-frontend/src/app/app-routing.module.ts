import {NgModule, inject} from '@angular/core';import {RouterModule, Routes} from '@angular/router';import {AutoLoginPartialRoutesGuard, OidcSecurityService} from 'angular-auth-oidc-client';import {ApplicationService} from './modules/core/services/application.service';import {of, switchMap, tap} from 'rxjs';import {HomeComponent} from './home/home/home.component';import {AppRoutingConstants} from './modules/shared/app-routing.constant';import {ForbiddenComponent} from './forbidden/forbidden/forbidden.component';const authGuard = () => {  const authService = inject(OidcSecurityService);  const applicationService = inject(ApplicationService);  return authService.checkAuth().pipe(    tap(authData => {      if (!authData.isAuthenticated) {        applicationService.login();      } else {        applicationService.postLogin();      }    }),    switchMap(loggedIn => of(loggedIn))  );};const routes: Routes = [  {path: '', redirectTo: 'home', pathMatch: 'full'},  {    path: AppRoutingConstants.HOME,    component: HomeComponent,    canActivate: [AutoLoginPartialRoutesGuard, authGuard]  },  {path: AppRoutingConstants.FORBIDDEN, component: ForbiddenComponent},  {path: '**', redirectTo: 'unknown-route'}];@NgModule({  imports: [RouterModule.forRoot(routes)],  exports: [RouterModule]})export class AppRoutingModule {}
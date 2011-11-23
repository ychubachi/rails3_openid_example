Rails3OpenidExample::Application.routes.draw do
  get "server/index"
  post "server/index"
  get "server/idp_xrds"
  get "server/user_page"
  get "server/user_xrds"
  get "server/wsdl"

  get "consumer/index"
  get "consumer/start"
  get "consumer/complete"

  get "login/index"
  get "login/submit"
  get "login/logout"
  root :to => 'login#index'

  match 'user/:username',      :controller => 'server', :action => 'user_page'
  match 'user/:username/xrds', :controller => 'server', :action => 'user_xrds'
  match 'server/xrds',         :controller => 'server', :action => 'idp_xrds'
  match 'server/decision',     :controller => 'server', :action => 'decision'

  # Allow downloading Web Service WSDL as a file with an extension
  # instead of a file named 'wsdl'
#  match ':controller/service.wsdl', :controller => 'server', :action => 'wsdl'

  # Install the default route as the lowest priority.
  match ':controller/:action/:id'

  # The priority is based upon order of creation:
  # first created -> highest priority.

  # Sample of regular route:
  #   match 'products/:id' => 'catalog#view'
  # Keep in mind you can assign values other than :controller and :action

  # Sample of named route:
  #   match 'products/:id/purchase' => 'catalog#purchase', :as => :purchase
  # This route can be invoked with purchase_url(:id => product.id)

  # Sample resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Sample resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Sample resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Sample resource route with more complex sub-resources
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', :on => :collection
  #     end
  #   end

  # Sample resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end

  # You can have the root of your site routed with "root"
  # just remember to delete public/index.html.
  # root :to => 'welcome#index'

  # See how all your routes lay out with "rake routes"

  # This is a legacy wild controller route that's not recommended for RESTful applications.
  # Note: This route will make all actions in every controller accessible via GET requests.
  # match ':controller(/:action(/:id(.:format)))'
end

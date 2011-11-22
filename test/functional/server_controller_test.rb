require 'test_helper'

class ServerControllerTest < ActionController::TestCase
  test "should get index" do
    get :index
    assert_response :success
  end

  test "should get idp_xrds" do
    get :idp_xrds
    assert_response :success
  end

  test "should get user_page" do
    get :user_page
    assert_response :success
  end

  test "should get user_xrds" do
    get :user_xrds
    assert_response :success
  end

end

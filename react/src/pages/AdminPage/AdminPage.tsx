import { AppstoreOutlined, HomeOutlined, LineChartOutlined, RightOutlined, ShopTwoTone, ShoppingCartOutlined, UserOutlined } from '@ant-design/icons';
import HeaderComponent from '../../components/HeaderComponent/HeaderComponent'
import {getItem} from '../../utils/utils'
import { Menu } from 'antd';
import './Admin.css'
import { useState } from 'react';
import AdminUser from '../../components/AdminComponent/AdminUserSystem/AdminUserSystem';
import AdminProduct from '../../components/AdminComponent/AdminProduct/AdminProduct';
import AdminOrder from '../../components/AdminComponent/AdminOrder/AdminOrder';
import AdminDashboard from '../../components/AdminComponent/AdminDashboard/AdminDashboard';
import { useNavigate } from 'react-router-dom';
import { BiSolidDiscount } from "react-icons/bi";

export default function AdminPage() {
  const navigate = useNavigate();
  const [keySelected, setKeySelected] = useState('Thống kê');
  const items = [
    getItem(<span>{'Thống kê'}</span>, 'Thống kê', <LineChartOutlined style={{fontSize:"20px",marginRight: '5px'}}/>),
    getItem(<span>{'Người dùng'}</span>, 'Người dùng', <UserOutlined style={{fontSize:"20px",marginRight: '5px'}}/>),
    getItem(<span>{'Sản phẩm'}</span>, 'Sản phẩm', <AppstoreOutlined style={{fontSize:"20px",marginRight: '5px'}} />),
    getItem(<span>{'Voucher'}</span>, 'Voucher', <BiSolidDiscount style={{fontSize:"20px",marginRight: '5px'}} />),
    getItem(<span>{'Đơn hàng'}</span>, 'Đơn hàng', <ShoppingCartOutlined style={{fontSize:"20px",marginRight: '5px'}} />,[
      getItem(<span>{'Đơn hàng trực tuyến'}</span>, 'Đơn hàng trực tuyến'),
      getItem(<span>{'Đơn hàng đã hủy'}</span>, 'Đơn hàng đã hủy'),
      getItem(<span>{'Đơn hàng đã duyệt'}</span>, 'Đơn hàng đã duyệt'),
    ]),   
  ];

  const handleOnCLick = ({ key } : any) => {
    setKeySelected(key)
  }

  const renderPage = (key : string) => {
    switch (key) {
        case 'Thống kê':
            return (
                <AdminDashboard />
            )
        case 'Người dùng':
            return (
                <AdminUser />
            )
        case 'Sản phẩm':
            return (
                <AdminProduct />
            )
        case 'Đơn hàng':
            return (
                <AdminOrder />
            )
      default:
        return <></>
    }
  }

  return (
    <div id='AdminPage'>
      <div className="menu">
        <div onClick={() => navigate('/')} className="title-header">
          <ShopTwoTone style={{fontSize:"35px"}}/>
          <span>TTNKT</span>
        </div>
        <Menu     
          //defaultSelectedKeys={'products'}  
          mode="inline"
          theme="dark"
          style={{
            //width: "20%",
            boxShadow: '1px 1px 2px #ccc',
            height: '100vh'
          }}
          items={items}
          onClick={handleOnCLick}
        />
      </div>
      <div className='manage-objects'>
        <HeaderComponent isShowCart={false} isShowMenu={false} isShowSearch={false}/>
        <div className='wrapper-body-admin'>
          <div className='path-system'>
            <div className='page-main' onClick={() => navigate('/')}><HomeOutlined />Trang chủ</div>
            <RightOutlined style={{margin:"0 5px"}}/> 
            <div>Quản lý hệ thống</div>
            <RightOutlined style={{margin:"0 5px"}}/> 
            <div>{keySelected}</div>
          </div>
          {renderPage(keySelected)}
        </div>
      </div>
    </div>
  )
}
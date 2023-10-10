import {AiOutlinePlus , AiOutlineCheckCircle , AiTwotoneEdit , AiFillDelete} from 'react-icons/ai'
import './Address.css'
import { Button, Input, Modal, Select , Form, Checkbox, Radio } from 'antd'
import { useEffect, useState } from 'react'
import { getListDistricts, getListProvincesCity, getListWards} from '../../utils/utils';
import { getAddressShipsByUser , createAddressShip, updateAddressShip, deleteAddressShip } from '../../services/userService';
import { AddressShipping } from '../../model/UserModal';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ToastContainer , toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

export default function AddressShipComponent() {
  const [isModalOpen , setIsOpenModal] = useState(false);
  const [listProvinces , setListProvinces] = useState([]);
  const [listDistricts , setListDistricts] = useState([]); 
  const [listWards , setListWards] = useState([]); 
  const [form] = Form.useForm();
  const [addressShipping , setAddressShipping] = useState<AddressShipping>({
    fullName : '',
    phone : '',
    province : '',
    district : '',
    ward : '',
    addressDetail : '',
    type : '',
    default : false
  })
  const [isFormEdit , setIsFormEdit] = useState(false)

  console.log(addressShipping)

  const handleCancelModal = () => {
    setIsOpenModal(false);
    form.resetFields();
    setListDistricts([]);
    setListWards([]);
  }

  useEffect(() => {
    const fetchProvincesCity = async () => {
      const data = await getListProvincesCity()
      setListProvinces(data)
    } 
    fetchProvincesCity();
  },[])

  const handleOnChangeInput = (e : any) => {
    setAddressShipping({
      ...addressShipping,
      [e.target.name] : e.target.name !== "default" ? e.target.value : e.target.checked
    })
  }

  const handleOnChangeProvince = async (nameCity : string, value : any) => {
    setAddressShipping({
      ...addressShipping ,
      province : nameCity,
      district : '',
      ward : ''
    })
    if(nameCity){
      setListDistricts([]);
      setListWards([]);
      form.setFieldsValue({
        district : "",
        ward : ""
      })
    }
    setListDistricts(await getListDistricts(value.key))
  }

  const handleOnChangeDistrict = async (nameDistrict : string, value : any) => {
    setAddressShipping({
      ...addressShipping ,
      district : nameDistrict
    })
    if(nameDistrict){
      setListWards([]);
      form.setFieldsValue({
        ward : ""
      })
    }
    setListWards(await getListWards(value.key))
  }

  const handleOnChangeWard = async (nameWard : string) => {
    setAddressShipping({
      ...addressShipping,
      ward : nameWard
    })
  }

  // handle get address ship by user

  const fetchGetAddressShipByUser = async () => {
    const res = await getAddressShipsByUser();
    return res.data
  }

  const queryAddressShip = useQuery({queryKey : ['addresses-ship-by-user'] , queryFn:fetchGetAddressShipByUser })
  const {data : listAddressShip} = queryAddressShip
  console.log(listAddressShip)

  // handle create new address ship

  const mutationCreateAddress = useMutation(
    async (data : AddressShipping) => {
      const res = await createAddressShip(data)
      return res
    }
  )

  const {data : responseCreate , isSuccess : isSuccessCreate} = mutationCreateAddress;

  useEffect(() => {
    if(isSuccessCreate && responseCreate?.success){
      toast.success(responseCreate?.message,{
        position: "top-right",
        autoClose: 5000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
      })
      handleCancelModal();
    }
  },[isSuccessCreate])

  const handleCreateAddressShip = () => {
    mutationCreateAddress.mutate({
      ...addressShipping,
    } , {
      onSettled : () => {
        queryAddressShip.refetch();
      }
    })
  }

  // handle edit address ship

  const mutationEditAddress = useMutation(
    async (data : AddressShipping) => {
      const res = await updateAddressShip(data);
      return res
    }
  )

  const {data : responseUpdate , isSuccess : isSuccessUpdate} = mutationCreateAddress;

  useEffect(() => {
    if(isSuccessUpdate && responseUpdate?.success){
      toast.success(responseUpdate?.message,{
        position: "top-right",
        autoClose: 5000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
      })
      handleCancelModal();
    }
  },[isSuccessUpdate])

  const handleEditAddressShip = async (address : AddressShipping) => {
    setIsOpenModal(true);
    form.setFieldsValue({
      ...address
    })
    setIsFormEdit(true);
    const province : any = listProvinces.find((province : any) => province['province_name'] === address.province);
    setListDistricts(await getListDistricts(province['province_id']));
    mutationEditAddress.mutate(address)
  }

  const mutationDeleteAddress = useMutation(
    async (data : number) => await deleteAddressShip(data)
  )

  const handleDeleteAddressShip = async (idAddressShip : number) => {
    if(confirm('Sure Delete this address ship')){
      mutationDeleteAddress.mutate(idAddressShip, {
        onSettled : () => {
          queryAddressShip.refetch();
        }
      })
    }
  }

  // useEffect(() => {
  //   const district : any = listDistricts.filter((district : any) => district['district_name'] === address.district);
  //   setListWards(await getListWards(district['district_id']));
  // })
  return (
    <div id='AddressShipComponent'>
      <ToastContainer/>
      <div className="add-address" onClick={() => setIsOpenModal(true)}>
        <AiOutlinePlus />
        <span>Add new address</span>
      </div>
      {listAddressShip && listAddressShip?.map((address : AddressShipping) => (
        <div className="address-ship">
          <div className="info">
            <div className="name">
              {address.fullName}
              {address.default && (
                <span>
                  <AiOutlineCheckCircle />
                  <span className='ms-2'>Default address</span>
                </span>
              )}
            </div>
            <div className="address" style={{marginBottom:5}}>
              <span>Address: </span>
              {address.addressDetail}
            </div>
            <div className="phone">
              <span>Phone: </span>
              {address.phone}
            </div>
          </div>
          <div className="action">
            <div className='act-edit' onClick={() => handleEditAddressShip(address)}>
              <AiTwotoneEdit/>
              Edit
            </div>
            {!address.default && (
              <div className='act-delete' onClick={() => handleDeleteAddressShip(address.id || 0)}>
                <AiFillDelete/>
                Delete
              </div>
            )}
          </div>
        </div>
      ))}
      <Modal title={isFormEdit ? "Chỉnh sửa địa chỉ" : "Thêm địa chỉ mới"} open={isModalOpen} footer={null} onCancel={handleCancelModal}>
        <Form
          name="wrap"
          form={form}
          labelCol={{ flex: '130px' }}
          labelAlign="left"
          labelWrap
          wrapperCol={{ flex: 1 }}
          colon={false}
          style={{ maxWidth: 600 }}         
          onFinish={handleCreateAddressShip}
        >
          <Form.Item label="Họ và tên" name="fullName" rules={[{ required: true }]}>
            <Input placeholder='Nhập Họ và tên' name='fullName' value={addressShipping.fullName} onChange={handleOnChangeInput}/>
          </Form.Item>

          <Form.Item label="Số điện thoại" name="phone" rules={[{ required: true }]}>
            <Input placeholder='Nhập Số điện thoại' name='phone' value={addressShipping.phone} onChange={handleOnChangeInput}/>
          </Form.Item>

          <Form.Item label="Province/city" name="province" rules={[{ required: true }]}>
            <Select
              defaultValue={'---Choice Province/city---'}
              onChange={handleOnChangeProvince}
            >
              <Select.Option value = {""}>---Choice Province/city---</Select.Option>
              {listProvinces.map(p => (
                <Select.Option key={p["province_id"]} value={p["province_name"]}>{p["province_name"]}</Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item label="District" name="district" rules={[{ required: true }]}>
            <Select
              //value={addressShipping.district}
              disabled = {listDistricts.length === 0}
              defaultValue={'---Choice District---'}
              onChange={handleOnChangeDistrict}
            >
              <Select.Option value = {""}>---Choice District---</Select.Option>
              {listDistricts.map(d => (
                <Select.Option key={d["district_id"]} value={d["district_name"]}>{d["district_name"]}</Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item label="Wards" name="ward" rules={[{ required: true }]}>
            <Select
              disabled = {listWards.length === 0}
              defaultValue={'---Choice Ward---'}
              onChange={handleOnChangeWard}
            >
              <Select.Option value={""}>---Choice Ward---</Select.Option>
              {listWards.map(w => (
                <Select.Option key={w["ward_id"]} value={w["ward_name"]}>{w["ward_name"]}</Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item label="Address" name="addressDetail" rules={[{ required: true }]}>
            <Input.TextArea 
              placeholder='ví dụ : 52 Trần Hưng Đạo ...' 
              name='addressDetail'
              value={addressShipping.addressDetail}
              onChange={handleOnChangeInput}
            />
          </Form.Item>

          <Form.Item label="Loại địa chỉ" name="type">
            <Radio.Group name="type" onChange={handleOnChangeInput} value={addressShipping.type}>
              <Radio value={"HOME"}>HOME</Radio>
              <Radio value={"WORK"}>WORK</Radio>
              <Radio value={"OTHER"}>OTHER</Radio>
            </Radio.Group>
          </Form.Item>

          <Form.Item label=" " name="default">
            <Checkbox name="default" onChange={handleOnChangeInput} value={addressShipping.default}/>
            Set as default address
          </Form.Item>

          <Form.Item label=" " >
            <Button type="primary" htmlType="submit">
              Cập nhật
            </Button>
          </Form.Item>
        </Form>
      </Modal>     
    </div>
  )
}

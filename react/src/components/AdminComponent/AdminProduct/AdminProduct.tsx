import { CloseOutlined , DeleteOutlined , EditOutlined } from '@ant-design/icons';
import { Upload , Button, Card, Form, Input, Space, Typography ,Select,Drawer, Row, Col } from 'antd';
import { useState ,useEffect, useMemo } from 'react';
import './AdminProduct.css'
import { BiPlus } from 'react-icons/bi';
import TableComponent from '../../TableComponent/TableComponent';
import { useMutation, useQuery } from '@tanstack/react-query';
import { createNewClothes, getAllClothes, getClothesById, updateClothes, uploadImageClothes } from '../../../services/clothesService';
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css';
import { UploadOutlined } from '@ant-design/icons';
import { toast } from 'react-toastify';
import { convertPrice, toastMSGObject } from '../../../utils/utils';
import { Action } from '../../../model/ActionModal';
import { API_URL } from '../../../utils/constants';

export default function AdminProduct() {

  const [form] = Form.useForm();
  const [isOpenDrawer , setisOpenDrawer] = useState(false) ;
  const [rowSelected , setRowSelected] = useState<any>({});
  const [value, setValue] = useState('');
  const [listCate , setListCate] = useState<any[]>([]);
  const [typeAction , setTypeAction] = useState<Action>(Action.ADD);

  const handleOnOpenDrawer = (action : Action) => {
    setisOpenDrawer(true);
    setTypeAction(action);
  }

  const handleOnCloseDrawer = () => {
    setisOpenDrawer(false);
    form.resetFields();
    form.setFieldsValue({ 
      classifyClothes: [1]// reset lại form classifyClothes thành 1 cái
    });
  }

  const newClothesCustome = () => {
    const formClothes = form.getFieldsValue();
    const classifyClothesCustome = formClothes.classifyClothes && formClothes.classifyClothes.map((item : any) => ({
      ...item,
      images: item?.images?.map((file : any) => file?.name)
    }))
    return {...formClothes , classifyClothes : classifyClothesCustome}
  }

  // Get all clothes via API

  const fetchGetAllProducts = async () => {
    const res = await getAllClothes();
    const {products , totalCount} = await res?.json();
    return {products , totalCount}
  }

  const queryAllProducts = useQuery(['all-product'], fetchGetAllProducts )
  const {data : listProducts , isLoading : isLoadingProducts} = queryAllProducts
  console.log(listProducts)

  // get detail clothes via API

  const fetchGetProductById = async (context : any) => {
    const idClothes = context?.queryKey[1]
    const res = await getClothesById(idClothes);
    return res;
  }

  const {data : productDetail , isSuccess : isSuccessProduct} = useQuery(['product-detail-1',rowSelected.id], fetchGetProductById , { enabled : !!rowSelected.id})

  console.log(form.getFieldsValue())

  useEffect(() => {
    if(isSuccessProduct && typeAction === Action.UPDATE && isOpenDrawer){
      console.log(typeAction)
      form.setFieldsValue({
        ...productDetail,
        discount : +productDetail.discount * 100,
        classifyClothes : productDetail.classifyClothes.map((classify : any) => ({
          ...classify,
          images : classify.images.map((img : string) => ({
            uid : -1,
            name : img,
            url : `${API_URL}/api/products/images/${img}`
          }))
        }))
      })
    }
  },[isSuccessProduct,isOpenDrawer])

  // get all categories 

  useEffect(() => {
    fetch(`${API_URL}/api/products/categories`)
      .then(res => res.json())
      .then(data => setListCate(data))
  },[])

  // add new clothes

  const mutationAddClo = useMutation(
    async (data : any) => {
      const res = await createNewClothes(data);
      return res.data
    },
    {
      onSuccess : () => {
        toast.success('Thêm sản phẩm mới thành công', toastMSGObject())
        handleOnCloseDrawer();
      },
      onError : () => {
        toast.error('Thêm sản phẩm mới thất bại' , toastMSGObject())
      },
      onSettled : () => {
        queryAllProducts.refetch();
      }
    }
  ) 

  const handleAddNewClothes = () => {
    mutationAddClo.mutate({
      ...newClothesCustome()
    })
  }

  // update clothes

  const mutationUpdateClo = useMutation(
    async (data : any) => {
      const res = await updateClothes(data);
      return res.data
    },
    {
      onSuccess : () => {
        toast.success('Cập nhật thông tin sản phẩm thành công', toastMSGObject())
        handleOnCloseDrawer();
      },
      onError : () => {
        toast.error('Cập nhật thông tin sản phẩm thất bại' , toastMSGObject())
      },
      onSettled : () => {
        queryAllProducts.refetch();
      }
    }
  ) 

  const handleUpdateClothes = () => {
    mutationUpdateClo.mutate({
      id : productDetail.id,
      ...newClothesCustome(),
      discount : newClothesCustome().discount / 100
    })
  }

  const renderAction = () => {
    return (
    <div>
      <EditOutlined 
        style={{ color: 'orange', fontSize: '30px', cursor: 'pointer' }} 
        onClick={() => handleOnOpenDrawer(Action.UPDATE)}
      />
    </div>
    )
  }

  const columns = [
    {
      title: 'Tên chi tiết',
      dataIndex: 'name',
      render: (text : string) => <span>{text}</span>,
      width : 400,
      sorter: (a : any,b : any) => a.name.length - b.name.length,
      isSearchProps : true
    },
    {
      title: 'Đơn vị lưu kho',
      dataIndex: 'sku',
      render: (text : string) => <span>{text}</span>,
      sorter: (a : any,b : any) => a.sku.length - b.sku.length,
      isSearchProps : true
    },
    {
      title: 'Giảm giá',
      dataIndex: 'discount',
      render: (text : number) => <span>{text*100} %</span>,
      sorter: (a : any,b : any) => a.discount - b.discount,
    },
    {
      title: 'Giá tiền',
      dataIndex: 'price',
      render: (text : number) => <span>{convertPrice(text)}</span>,
      sorter: (a : any,b : any) => a.price - b.price,
      filters: [
          {
              text: 'Dưới 50k',
              value: [0,50000],
          },
          {
              text: 'Từ 50k đến 200k',
              value: [50000,200000],
          },
          {
              text: 'Từ 200k đến 500k',
              value: [200000,500000],
          },
          {
              text: 'Từ 500k đến 1000k',
              value: [500000,1000000],
          },
          {
              text: 'Trên 1000k',
              value: [1000000],
          },
        ],
      onFilter: ([start ,end] : number[], record : any) => (end ? (record.price <= end && record.price >= start) : (record.price >= start)),
    },
    {
        title: 'Danh mục',
        dataIndex: 'category',
    },
    {
        title: 'Action',
        dataIndex: 'action',
        render: renderAction
    }
  ];

  return (
    <div id='AdminProduct'>
      <div className="clo-act-btn">
        <div className="total-clo">
          Tổng số lượng sản phẩm : {listProducts?.totalCount}
        </div>
        <Button type="primary" onClick={() => handleOnOpenDrawer(Action.ADD)}>
          <BiPlus/>
          Add new clothes
        </Button>
      </div>

      <TableComponent 
          columns={columns} 
          listData={listProducts?.products} 
          isLoading={isLoadingProducts}
          onRow={(record : any, rowIndex : any) => {
              return {
                  onClick : (event : any) => {
                      setRowSelected(record)
                  }
              }
          }}  
          isRowSelection={false}                  
      />

      {/** form add clothes */}
      <Drawer
        title={typeAction === Action.ADD ? 'Create a new clothes' : 'Update information clothes'}
        width={980}
        onClose={handleOnCloseDrawer}
        open={isOpenDrawer}
        bodyStyle={{paddingBottom:"80px"}}
        extra={
          <Space>
            <Button onClick={handleOnCloseDrawer}>Cancel</Button>
            <Button 
              onClick={typeAction === Action.ADD ? handleAddNewClothes : handleUpdateClothes} 
              type="primary"
            >
              {typeAction.toLocaleLowerCase()}
            </Button>
          </Space>
        }
      >
        <Form
          labelCol={{ span: 8 }}
          wrapperCol={{ span: 16 }}
          form={form}
          // style={{ maxWidth: 600 }}
          autoComplete="off"
          initialValues={{ classifyClothes: [{}] }}
        >
          <Row gutter={32}>
            <Col span={14} style={{borderRight: '1px solid #e1e1e1'}}>
              <Form.Item name="name" label="Name" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="sku" label="Đơn vị lưu kho" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item 
                name="price" label="Price" 
                rules={[{ required: true }]}
                getValueFromEvent={(event) => {
                  const value = parseFloat(event.target.value);
                  return isNaN(value) ? undefined : value;
                }}
              >
                <Input type='number'/>
              </Form.Item>
              <Form.Item 
                name="discount" label="Discount" 
                rules={[{ required: true }]}
                getValueFromEvent={(event) => {
                  const value = parseFloat(event.target.value);
                  return isNaN(value) ? undefined : value;
                }}
              >
                <Input type='number' />
              </Form.Item>
              <Form.Item name="categoryId" label="Danh mục sản phẩm" initialValue={listCate[0]?.id} rules={[{ required: true }]}>
                <Select>
                  {listCate.map(cate => (
                    <Select.Option value={cate.id}>{cate.name}</Select.Option>
                  ))}
                </Select>
              </Form.Item>
              <Form.Item 
                  name="description" 
                  label="Detail description"
                  className='des-field'
                  wrapperCol={{ span: 24 }}
              >
                <ReactQuill style={{height:"300px"}} theme="snow" value={value} onChange={setValue} />
              </Form.Item>
            </Col>
            <Col span={10}>
              <Form.List name="classifyClothes">
                {(fields, { add, remove }) => (
                  <div style={{ display: 'flex', rowGap: 16, flexDirection: 'column' }}>
                    {fields.map((field) => (
                      <Card
                        size="small"
                        title={`ClassifyClothes ${field.name + 1}`}
                        key={field.key}
                        extra={
                          <CloseOutlined
                            onClick={() => {
                              remove(field.name);
                            }}
                          />
                        }
                      >
                        <Form.Item label="Color" name={[field.name, 'color']}>
                          <Input/>
                        </Form.Item>

                        <Form.Item label="Images" name={[field.name, 'images']} valuePropName="fileList"
                          getValueFromEvent={(e) => e?.fileList}
                        >
                          <Upload 
                            onChange={async (info) => {
                              await uploadImageClothes(info.file);
                            }}
                            beforeUpload = {(file) => {
                              return false
                            }}
                            listType="picture-card"
                          >
                            <Button icon={<UploadOutlined />}>Upload</Button>
                          </Upload>
                        </Form.Item>

                        {/* Nest Form.List */}
                        <Form.Item label="Quantities">
                          <Form.List name={[field.name, 'quantities']}>
                            {(subFields, subOpt) => (
                              <div style={{ display: 'flex', flexDirection: 'column', rowGap: 16 }}>
                                {subFields.map((subField) => (
                                  <Space key={subField.key}>
                                    <Form.Item noStyle name={[subField.name,'size']} initialValue={'M'}>
                                      <Select>
                                        <Select.Option value={'M'}>M</Select.Option>
                                        <Select.Option value={'L'}>L</Select.Option>
                                        <Select.Option value={'XL'}>XL</Select.Option>
                                        <Select.Option value={'2XL'}>2XL</Select.Option>
                                      </Select>
                                    </Form.Item>
                                    <Form.Item 
                                      noStyle name={[subField.name,'quantityInStock']}
                                      getValueFromEvent={(event) => {
                                        const value = parseFloat(event.target.value);
                                        return isNaN(value) ? undefined : value;
                                      }}
                                    >
                                      <Input type='number' placeholder="Số lượng" />
                                    </Form.Item>
                                    <CloseOutlined
                                      onClick={() => {
                                        subOpt.remove(subField.name);
                                      }}
                                    />
                                  </Space>
                                ))}
                                <Button type="dashed" onClick={() => subOpt.add()} block>
                                  + Add extra size
                                </Button>
                              </div>
                            )}
                          </Form.List>
                        </Form.Item>
                      </Card>
                    ))}

                    <Button type="dashed" onClick={() => add()} block>
                      + Add extra classify clothes
                    </Button>
                  </div>
                )}
              </Form.List>
            </Col>
          </Row>
          
          <Form.Item noStyle shouldUpdate>
            {() => (
              <Typography style={{marginTop:"30px"}} >
                <pre>{JSON.stringify(newClothesCustome(), null, 2)}</pre>
              </Typography>
            )}
          </Form.Item>
        </Form>      
      </Drawer>
    </div>
  )
}

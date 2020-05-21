using CloudField.Framework.Dependency;
using Middleware.DataTransport.Core.API;
using Middleware.Target.Core;
using Middleware.Target.Core.Models;
using Middleware.Target.Core.Models.Tplus12_3;
using Middleware.Target.Core.Models.Tplus12_3.Models;
using Middleware.Target.TPlus_V12_3.Request;
using Middleware.Target.TPlus_V12_3.Response;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;

namespace Middleware.Target.TPlus_V12_3
{
    public class TPlusRepository : ITPlusRepository, ITransientDependency
    {
        private readonly IAPIClient _Client;
        public TPlusRepository(BaseAPIConfig config)
        {
            _Client = new TPlusClient(config);
        }
        public CreateVoucherBatchResponse CreateBatchVoucherRequest(VoucherBatchSaveModel voucherBatchSaveModel)
        {
            var request = new CreateVoucherBatchRequest();
            var parmsDic = new Dictionary<string, object>();
            parmsDic.Add("_args", voucherBatchSaveModel);
            request.SetPostParameters(parmsDic);
            return _Client.Excute(request);
        }
        public string CreateBatchVoucher(VoucherBatchSaveModel voucherBatchSaveModel)
        {
            var response = CreateBatchVoucherRequest(voucherBatchSaveModel);
            if (response == null)
            {
                return "";

            }
            else
            {
                return response.RestException.message;
            }
        }
        public List<TplusDetailsModel> QueryAllAccount()
        {
            var response = QueryAccountRequest();
            var list = new List<TplusDetailsModel>();
            if (response != null && response.DataTable != null && response.DataTable.Rows != null && response.DataTable.Rows.Length > 0)
            {
                list = response.DataTable.Rows.Select(x => new TplusDetailsModel
                {
                    AccountTypeDTO_Name = x.AccountTypeDTO_Name,
                    code = x.code,
                    DCDirection_Name = x.DCDirection_Name,
                    depth = x.depth,
                    id = x.id,
                    shorthand = x.shorthand,
                    isauxacccustomer = x.isauxacccustomer,
                    isauxaccdepartment = x.isauxaccdepartment,
                    isauxaccinventory = x.isauxaccinventory,
                    isauxaccperson = x.isauxaccperson,
                    isauxaccproject = x.isauxaccproject,
                    name = x.name,
                    isEndNode = x.isEndNode
                }).ToList();
                list.ForEach(t =>
                {
                    var auxaccName = "";
                    if (t.isauxacccustomer == 1)
                    {
                        auxaccName = "往来单位";
                    }
                    if (t.isauxaccdepartment == 1)
                    {
                        auxaccName += "," + "部门";
                    }
                    if (t.isauxaccinventory == 1)
                    {
                        auxaccName += "," + "存货";
                    }
                    if (t.isauxaccperson == 1)
                    {
                        auxaccName += "," + "个人";
                    }
                    if (t.isauxaccproject == 1)
                    {
                        auxaccName += "," + "项目";
                    }
                    t.auxaccName = auxaccName.TrimStart(',');
                });
            }
            return list;
        }
        public QueryAccountResponse QueryAccountRequest()
        {
            var request = new QueryAccountRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QuertyEntity() { dto = new BasicDto { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            return _Client.Excute(request);
        }
        public QueryVoucherResponse QueryVoucherRequest(string externalCode)
        {
            var request = new QueryVoucherRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryVoucherEntity { dtos = new VoucherDto[0].Append(new VoucherDto { ExternalCode = externalCode }).ToArray() };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            return _Client.Excute(request);
        }
        public QueryVoucherResponse QueryVoucherRequest(List<string> ids)
        {
            var request = new QueryVoucherRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryVoucherEntity();
            var dtos = new List<VoucherDto>();
            ids.ForEach(t =>
           {
               dtos.Add(new VoucherDto { ExternalCode = t });
           });
            parms.dtos = dtos.ToArray();
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            return _Client.Excute(request);
        }
        public List<VoucherDetailInfos> QueryVouchers(List<string> ids)
        {
            var response = QueryVoucherRequest(ids);
            var list = new List<VoucherDetailInfos>();
            if (response != null && response.Rows != null && response.Rows.Length > 0)
            {
                list = response.Rows.ToList();
            }
            return list;
        }
        public List<VoucherDetailInfos> QueryVouchers(string externalCode)
        {
            var response = QueryVoucherRequest(externalCode);
            var list = new List<VoucherDetailInfos>();
            if (response != null && response.Rows != null && response.Rows.Length > 0)
            {
                list = response.Rows.ToList();
            }
            return list;
        }
        public CreateVoucherResponse CreateVoucherRequest(VoucherSaveModel voucherSaveModel)
        {
            var request = new CreateVoucherRequest();
            var parmsDic = new Dictionary<string, object>();
            parmsDic.Add("_args", JsonConvert.SerializeObject(voucherSaveModel));
            request.SetPostParameters(parmsDic);
            return _Client.Excute(request);
        }

        public string CreateVoucher(VoucherSaveModel voucherSaveModel)
        {
            var response = CreateVoucherRequest(voucherSaveModel);
            if (response == null)
            {
                return "";
            }
            else
            {
                return response.message;
            }
        }
        /// <summary>
        /// 查询往来单位分类
        /// </summary>
        /// <returns></returns>
        public string QueryPartnerClass()
        {
            var request = new PartnerClassQueryRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new BaseQueryEntity() { param = new Param { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            if (result != null)
            {
                var entity = JsonConvert.DeserializeObject<List<PartnerClassQueryEntity>>(result.ToString());
                if (entity != null && entity.FirstOrDefault() != null)
                {
                    return entity.FirstOrDefault().Code;
                }
                else
                {
                    return "";
                }
            }
            else
            {
                return "";
            }
        }
        public List<CommonQueryResult> QueryAllPartnerClass()
        {
            var request = new PartnerClassQueryRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new BaseQueryEntity() { param = new Param { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var list = new List<CommonQueryResult>();
            if (result != null)
            {
                list = JsonConvert.DeserializeObject<List<CommonQueryResult>>(result.ToString());
            }
            return list;
        }

        public string AddPartner(PartnerAddEntityDto partnerEntity)
        {
            var request = new PartnerAddRequest();
            var parmsDic = new Dictionary<string, object>();
            parmsDic.Add("_args", JsonConvert.SerializeObject(partnerEntity));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<string>(request);
            if (result != null)
            {
                return result;
            }
            else
            {
                return "";
            }
        }

        /// <summary>
        /// 查询往来单位
        /// </summary>
        /// <param name="partnerCode"></param>
        /// <returns></returns>
        public string QueryPartner(string partnerCode)
        {
            var request = new QueryPartnerRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryPartnerDto { param = new QueryPartnerParam { Code = partnerCode } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var resultStr = "";
            if (result != null)
            {
                var resultMsg = JsonConvert.DeserializeObject<List<QueryPartnerResult>>(result.ToString());
                if (resultMsg != null && resultMsg.Count > 0)
                {
                    resultStr = resultMsg.FirstOrDefault().Code;
                }
            }
            return resultStr;
        }

        public List<CommonQueryResult> QueryPartnerList()
        {
            var request = new QueryPartnerRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryPartnerDto { param = new QueryPartnerParam { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var resultStr = new List<CommonQueryResult>();
            if (result != null)
            {
                var resultMsg = JsonConvert.DeserializeObject<List<CommonQueryResult>>(result.ToString());
                if (resultMsg != null && resultMsg.Count > 0)
                {
                    resultStr = resultMsg;
                }
            }
            return resultStr;
        }
        ///仓库
        ///
        //部门
        public List<CommonQueryResult> GetQueryDepartmentResult()
        {
            var request = new QueryDepartmentRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QuertyEntity() { dto = new BasicDto { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var resultStr = new List<CommonQueryResult>();
            if (result != null)
            {
                var resultMsg = JsonConvert.DeserializeObject<List<CommonQueryResult>>(result.ToString());
                if (resultMsg != null && resultMsg.Count > 0)
                {
                    resultStr = resultMsg;
                }
            }
            return resultStr;
        }

        public List<CommonQueryResult> GetQueryWarehouseResult()
        {
            var request = new QueryWarehouseRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryPartnerDto() { param = new QueryPartnerParam { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var resultStr = new List<CommonQueryResult>();

            if (result != null)
            {
                var resultMsg = JsonConvert.DeserializeObject<List<CommonQueryResult>>(result.ToString());
                if (resultMsg != null && resultMsg.Count > 0)
                {
                    resultStr = resultMsg;
                }
            }
            return resultStr;
        }

        //存货
        public List<CommonQueryResult> GetQueryInventoryResult()
        {
            var request = new QueryInventoryRequest();
            var parmsDic = new Dictionary<string, object>();
            var parms = new QueryPartnerDto() { param = new QueryPartnerParam { } };
            parmsDic.Add("_args", JsonConvert.SerializeObject(parms));
            request.SetPostParameters(parmsDic);
            var result = _Client.Excute<JArray>(request);
            var resultStr = new List<CommonQueryResult>();

            if (result != null)
            {
                var resultMsg = JsonConvert.DeserializeObject<List<CommonQueryResult>>(result.ToString());
                if (resultMsg != null && resultMsg.Count > 0)
                {
                    resultStr = resultMsg;
                }
            }
            return resultStr;
        }

        //
        public List<CommonQueryResult> GetAllDocType()
        {
            var request = new QueryDocTypeRequest();
            var response = _Client.Excute(request);
            var list = new List<CommonQueryResult>();
            if (response != null && response.DataTable != null && response.DataTable.Rows != null && response.DataTable.Rows.Length > 0)
            {
                list = response.DataTable.Rows.Select(x => new CommonQueryResult
                {
                    Code = x.code,
                    Name = x.name
                }).ToList();
            }
            return list;
        }

    }
}

using JuiceShopDotNet.Safe.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Reflection;

namespace JuiceShopDotNet.Safe.Auth;

[AttributeUsage(AttributeTargets.Property)]
public class AuthorizeOrderAttribute(string modelParameter) : Attribute, IActionFilter
{
    private readonly string _modelParameter = modelParameter;

    public void OnActionExecuted(ActionExecutedContext context)
    { /* Nothing to do here */ }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        var dataStore = context.HttpContext.RequestServices.GetService<ApplicationDbContext>();

        var bindingValue = context.ActionArguments.GetValueForPath(_modelParameter);
        if (bindingValue == null)
        {
            context.Result = new BadRequestObjectResult(new { message = "Invalid order number" });
            return;
        }

        if (!int.TryParse(bindingValue, out int orderID))
        {
            context.Result = new BadRequestObjectResult(new { message = "Invalid order number" });
            return;
        }

        var userID = context.HttpContext.User.GetUserID();
        var order = dataStore.Orders.SingleOrDefault(o => o.OrderID == orderID && o.JuiceShopUserID == userID);

        if (order == null)
            context.Result = new BadRequestObjectResult(new { message = "Invalid order number" });
    }
}

public static class IDictionaryExtensionMethods
{
    public static string? GetValueForPath(this IDictionary<string, object> parameters, string path)
    {
        var pathParts = path.Split(".");

        var parent = parameters.SingleOrDefault(p => p.Key == pathParts[0]);

        if (string.IsNullOrEmpty(parent.Key))
            throw new InvalidOperationException($"Cannot find a binding property with the name {pathParts[0]}");

        if (pathParts.Length == 1)
        {
            if (parent.Value == null)
                return null;
            else
                return parent.Value.ToString();
        }

        int currentIndex = 1;
        object currentObject = parent.Value;

        while (currentIndex < pathParts.Length)
        {
            if (currentObject == null)
                throw new NullReferenceException($"Cannot find a value for {pathParts[currentIndex]} because {pathParts[currentIndex - 1]} is null");

            var memberInfo = currentObject.GetType().GetMember(pathParts[currentIndex]);

            if (memberInfo == null || memberInfo.Length == 0)
                throw new InvalidOperationException($"Cannot find a binding property on object {pathParts[currentIndex - 1]} with the name {pathParts[currentIndex]}");

            currentObject = memberInfo[0].MemberType switch
            {
                MemberTypes.Field => ((FieldInfo)memberInfo[0]).GetValue(currentObject),
                MemberTypes.Property => ((PropertyInfo)memberInfo[0]).GetValue(currentObject),
                _ => throw new NotImplementedException(),
            };
            currentIndex++;
        }

        if (currentObject == null)
            return null;
        else
            return currentObject.ToString();
    }
}
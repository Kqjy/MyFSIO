use sqlparser::ast as sql;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use super::value::Value;

#[derive(Debug, Clone)]
pub struct SelectPlan {
    pub projection: Vec<ProjItem>,
    pub where_clause: Option<Expr>,
    pub limit: Option<u64>,
    pub aggregates: Vec<AggSpec>,
}

#[derive(Debug, Clone)]
pub enum ProjItem {
    Wildcard,
    Expr { expr: Expr, name: String },
}

#[derive(Debug, Clone)]
pub struct AggSpec {
    pub func: AggFunc,
    pub arg: Option<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggFunc {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastType {
    Int,
    Float,
    Str,
    Bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    And,
    Or,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Concat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarFunc {
    Lower,
    Upper,
    Trim,
    Ltrim,
    Rtrim,
    CharLength,
    Substring,
    Coalesce,
    Nullif,
    Abs,
    Ceil,
    Floor,
    Round,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Column {
        name: String,
        path: Vec<String>,
    },
    Literal(Value),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    IsNull {
        expr: Box<Expr>,
        negated: bool,
    },
    Like {
        expr: Box<Expr>,
        pattern: Box<Expr>,
        escape: Option<char>,
        negated: bool,
        case_insensitive: bool,
    },
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    InList {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    Case {
        operand: Option<Box<Expr>>,
        branches: Vec<(Expr, Expr)>,
        else_result: Option<Box<Expr>>,
    },
    Cast {
        expr: Box<Expr>,
        target: CastType,
    },
    Func(ScalarFunc, Vec<Expr>),
    Aggregate(usize),
}

struct PlanBuilder {
    table_names: Vec<String>,
    aggregates: Vec<AggSpec>,
}

pub fn plan_query(sql_text: &str) -> Result<SelectPlan, String> {
    let dialect = GenericDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql_text).map_err(|e| format!("SQL parse error: {}", e))?;
    if statements.len() != 1 {
        return Err("Expression must contain exactly one SELECT statement".to_string());
    }
    let query = match statements.into_iter().next().unwrap() {
        sql::Statement::Query(q) => q,
        _ => return Err("Only SELECT statements are supported".to_string()),
    };

    if query.with.is_some() {
        return Err("WITH clauses are not supported".to_string());
    }
    if let Some(order_by) = &query.order_by {
        let _ = order_by;
        return Err("ORDER BY is not supported".to_string());
    }
    if query.fetch.is_some() {
        return Err("FETCH/OFFSET are not supported".to_string());
    }

    let limit = match &query.limit_clause {
        None => None,
        Some(sql::LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) => {
            if offset.is_some() || !limit_by.is_empty() {
                return Err("FETCH/OFFSET are not supported".to_string());
            }
            match limit {
                None => None,
                Some(sql::Expr::Value(v)) => match &v.value {
                    sql::Value::Number(n, _) => Some(
                        n.parse::<u64>()
                            .map_err(|_| "LIMIT must be a non-negative integer".to_string())?,
                    ),
                    _ => return Err("LIMIT must be a non-negative integer".to_string()),
                },
                Some(_) => return Err("LIMIT must be a non-negative integer".to_string()),
            }
        }
        Some(sql::LimitClause::OffsetCommaLimit { .. }) => {
            return Err("FETCH/OFFSET are not supported".to_string());
        }
    };

    let select = match *query.body {
        sql::SetExpr::Select(select) => select,
        _ => return Err("Only plain SELECT queries are supported".to_string()),
    };

    if select.distinct.is_some() {
        return Err("SELECT DISTINCT is not supported".to_string());
    }
    if select.having.is_some() {
        return Err("HAVING is not supported".to_string());
    }
    match &select.group_by {
        sql::GroupByExpr::Expressions(exprs, _) if exprs.is_empty() => {}
        sql::GroupByExpr::Expressions(_, _) | sql::GroupByExpr::All(_) => {
            return Err("GROUP BY is not supported".to_string());
        }
    }

    if select.from.len() != 1 {
        return Err("FROM must reference exactly the S3 object".to_string());
    }
    let table = &select.from[0];
    if !table.joins.is_empty() {
        return Err("JOINs are not supported".to_string());
    }
    let mut table_names: Vec<String> = vec!["s3object".to_string()];
    match &table.relation {
        sql::TableFactor::Table {
            name, alias, args, ..
        } => {
            if args.is_some() {
                return Err("Table functions are not supported in FROM".to_string());
            }
            let base = match name.0.as_slice() {
                [part] => part.as_ident().map(|i| i.value.to_ascii_lowercase()),
                _ => None,
            };
            if base.as_deref() != Some("s3object") {
                return Err("FROM must reference S3Object".to_string());
            }
            if let Some(alias) = alias {
                table_names.push(alias.name.value.to_ascii_lowercase());
            }
        }
        _ => return Err("FROM must reference S3Object".to_string()),
    }

    let mut builder = PlanBuilder {
        table_names,
        aggregates: Vec::new(),
    };

    let mut projection = Vec::with_capacity(select.projection.len());
    for (idx, item) in select.projection.iter().enumerate() {
        match item {
            sql::SelectItem::Wildcard(_) => projection.push(ProjItem::Wildcard),
            sql::SelectItem::QualifiedWildcard(kind, _) => {
                let qualifier_ok = match kind {
                    sql::SelectItemQualifiedWildcardKind::ObjectName(name) => {
                        match name.0.as_slice() {
                            [part] => part
                                .as_ident()
                                .map(|i| {
                                    builder.table_names.contains(&i.value.to_ascii_lowercase())
                                })
                                .unwrap_or(false),
                            _ => false,
                        }
                    }
                    sql::SelectItemQualifiedWildcardKind::Expr(_) => false,
                };
                if !qualifier_ok {
                    return Err(format!(
                        "The wildcard qualifier in '{}' must be the S3Object table or its alias",
                        item
                    ));
                }
                projection.push(ProjItem::Wildcard);
            }
            sql::SelectItem::UnnamedExpr(e) => {
                let expr = builder.convert(e, true)?;
                let name = default_name(&expr, idx);
                projection.push(ProjItem::Expr { expr, name });
            }
            sql::SelectItem::ExprWithAlias { expr, alias } => {
                let expr = builder.convert(expr, true)?;
                projection.push(ProjItem::Expr {
                    expr,
                    name: alias.value.clone(),
                });
            }
            sql::SelectItem::ExprWithAliases { .. } => {
                return Err("Multiple aliases per projection are not supported".to_string());
            }
        }
    }
    if projection.is_empty() {
        return Err("SELECT list cannot be empty".to_string());
    }

    let where_clause = match &select.selection {
        Some(e) => Some(builder.convert(e, false)?),
        None => None,
    };

    if !builder.aggregates.is_empty() {
        for item in &projection {
            if matches!(item, ProjItem::Wildcard) {
                return Err("Cannot mix aggregate functions with * projections".to_string());
            }
            if let ProjItem::Expr { expr, .. } = item {
                if contains_bare_column(expr) {
                    return Err(
                        "Cannot mix aggregate functions with plain column references".to_string(),
                    );
                }
            }
        }
    }

    Ok(SelectPlan {
        projection,
        where_clause,
        limit,
        aggregates: builder.aggregates,
    })
}

fn default_name(expr: &Expr, idx: usize) -> String {
    match expr {
        Expr::Column { name, path } => path.last().cloned().unwrap_or_else(|| name.clone()),
        _ => format!("_{}", idx + 1),
    }
}

fn contains_bare_column(expr: &Expr) -> bool {
    match expr {
        Expr::Column { .. } => true,
        Expr::Literal(_) | Expr::Aggregate(_) => false,
        Expr::Unary(_, e) => contains_bare_column(e),
        Expr::Binary(_, a, b) => contains_bare_column(a) || contains_bare_column(b),
        Expr::IsNull { expr, .. } => contains_bare_column(expr),
        Expr::Like { expr, pattern, .. } => {
            contains_bare_column(expr) || contains_bare_column(pattern)
        }
        Expr::Between {
            expr, low, high, ..
        } => contains_bare_column(expr) || contains_bare_column(low) || contains_bare_column(high),
        Expr::InList { expr, list, .. } => {
            contains_bare_column(expr) || list.iter().any(contains_bare_column)
        }
        Expr::Case {
            operand,
            branches,
            else_result,
        } => {
            operand
                .as_deref()
                .map(contains_bare_column)
                .unwrap_or(false)
                || branches
                    .iter()
                    .any(|(c, r)| contains_bare_column(c) || contains_bare_column(r))
                || else_result
                    .as_deref()
                    .map(contains_bare_column)
                    .unwrap_or(false)
        }
        Expr::Cast { expr, .. } => contains_bare_column(expr),
        Expr::Func(_, args) => args.iter().any(contains_bare_column),
    }
}

impl PlanBuilder {
    fn convert(&mut self, expr: &sql::Expr, allow_agg: bool) -> Result<Expr, String> {
        match expr {
            sql::Expr::Identifier(ident) => Ok(self.column_from_parts(vec![ident.value.clone()])),
            sql::Expr::CompoundIdentifier(parts) => {
                Ok(self.column_from_parts(parts.iter().map(|i| i.value.clone()).collect()))
            }
            sql::Expr::CompoundFieldAccess { root, access_chain } => {
                let mut parts: Vec<String> = match path_parts(root) {
                    Some(parts) => parts,
                    None => return Err(format!("Unsupported SQL expression: {}", root)),
                };
                for access in access_chain {
                    match access {
                        sql::AccessExpr::Dot(inner) => match path_parts(inner) {
                            Some(more) => parts.extend(more),
                            None => {
                                return Err(format!("Unsupported column path segment: {}", inner));
                            }
                        },
                        sql::AccessExpr::Subscript(_) => {
                            return Err(
                                "Array subscripts are not supported in column paths".to_string()
                            );
                        }
                    }
                }
                Ok(self.column_from_parts(parts))
            }
            sql::Expr::Value(v) => literal_value(&v.value),
            sql::Expr::Nested(inner) => self.convert(inner, allow_agg),
            sql::Expr::UnaryOp { op, expr } => {
                let inner = self.convert(expr, allow_agg)?;
                match op {
                    sql::UnaryOperator::Not => Ok(Expr::Unary(UnaryOp::Not, Box::new(inner))),
                    sql::UnaryOperator::Minus => Ok(Expr::Unary(UnaryOp::Neg, Box::new(inner))),
                    sql::UnaryOperator::Plus => Ok(inner),
                    other => Err(format!("Unsupported unary operator: {}", other)),
                }
            }
            sql::Expr::BinaryOp { left, op, right } => {
                let op = match op {
                    sql::BinaryOperator::And => BinOp::And,
                    sql::BinaryOperator::Or => BinOp::Or,
                    sql::BinaryOperator::Eq => BinOp::Eq,
                    sql::BinaryOperator::NotEq => BinOp::NotEq,
                    sql::BinaryOperator::Lt => BinOp::Lt,
                    sql::BinaryOperator::LtEq => BinOp::LtEq,
                    sql::BinaryOperator::Gt => BinOp::Gt,
                    sql::BinaryOperator::GtEq => BinOp::GtEq,
                    sql::BinaryOperator::Plus => BinOp::Plus,
                    sql::BinaryOperator::Minus => BinOp::Minus,
                    sql::BinaryOperator::Multiply => BinOp::Multiply,
                    sql::BinaryOperator::Divide => BinOp::Divide,
                    sql::BinaryOperator::Modulo => BinOp::Modulo,
                    sql::BinaryOperator::StringConcat => BinOp::Concat,
                    other => return Err(format!("Unsupported operator: {}", other)),
                };
                Ok(Expr::Binary(
                    op,
                    Box::new(self.convert(left, allow_agg)?),
                    Box::new(self.convert(right, allow_agg)?),
                ))
            }
            sql::Expr::IsNull(inner) => Ok(Expr::IsNull {
                expr: Box::new(self.convert(inner, allow_agg)?),
                negated: false,
            }),
            sql::Expr::IsNotNull(inner) => Ok(Expr::IsNull {
                expr: Box::new(self.convert(inner, allow_agg)?),
                negated: true,
            }),
            sql::Expr::IsTrue(inner) => Ok(Expr::Binary(
                BinOp::Eq,
                Box::new(self.convert(inner, allow_agg)?),
                Box::new(Expr::Literal(Value::Bool(true))),
            )),
            sql::Expr::IsFalse(inner) => Ok(Expr::Binary(
                BinOp::Eq,
                Box::new(self.convert(inner, allow_agg)?),
                Box::new(Expr::Literal(Value::Bool(false))),
            )),
            sql::Expr::Like {
                negated,
                expr,
                pattern,
                escape_char,
                ..
            } => Ok(Expr::Like {
                expr: Box::new(self.convert(expr, allow_agg)?),
                pattern: Box::new(self.convert(pattern, allow_agg)?),
                escape: escape_char_value(escape_char)?,
                negated: *negated,
                case_insensitive: false,
            }),
            sql::Expr::ILike {
                negated,
                expr,
                pattern,
                escape_char,
                ..
            } => Ok(Expr::Like {
                expr: Box::new(self.convert(expr, allow_agg)?),
                pattern: Box::new(self.convert(pattern, allow_agg)?),
                escape: escape_char_value(escape_char)?,
                negated: *negated,
                case_insensitive: true,
            }),
            sql::Expr::Between {
                expr,
                negated,
                low,
                high,
            } => Ok(Expr::Between {
                expr: Box::new(self.convert(expr, allow_agg)?),
                low: Box::new(self.convert(low, allow_agg)?),
                high: Box::new(self.convert(high, allow_agg)?),
                negated: *negated,
            }),
            sql::Expr::InList {
                expr,
                list,
                negated,
            } => Ok(Expr::InList {
                expr: Box::new(self.convert(expr, allow_agg)?),
                list: list
                    .iter()
                    .map(|e| self.convert(e, allow_agg))
                    .collect::<Result<Vec<_>, _>>()?,
                negated: *negated,
            }),
            sql::Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                let operand = match operand {
                    Some(op) => Some(Box::new(self.convert(op, allow_agg)?)),
                    None => None,
                };
                let mut branches = Vec::with_capacity(conditions.len());
                for when in conditions {
                    branches.push((
                        self.convert(&when.condition, allow_agg)?,
                        self.convert(&when.result, allow_agg)?,
                    ));
                }
                let else_result = match else_result {
                    Some(e) => Some(Box::new(self.convert(e, allow_agg)?)),
                    None => None,
                };
                Ok(Expr::Case {
                    operand,
                    branches,
                    else_result,
                })
            }
            sql::Expr::Cast {
                expr,
                data_type,
                kind,
                ..
            } => {
                if !matches!(kind, sql::CastKind::Cast | sql::CastKind::DoubleColon) {
                    return Err("Only CAST(expr AS type) is supported".to_string());
                }
                Ok(Expr::Cast {
                    expr: Box::new(self.convert(expr, allow_agg)?),
                    target: cast_target(data_type)?,
                })
            }
            sql::Expr::Substring {
                expr,
                substring_from,
                substring_for,
                ..
            } => {
                let mut args = vec![self.convert(expr, allow_agg)?];
                match substring_from {
                    Some(from) => args.push(self.convert(from, allow_agg)?),
                    None => args.push(Expr::Literal(Value::Int(1))),
                }
                if let Some(len) = substring_for {
                    args.push(self.convert(len, allow_agg)?);
                }
                Ok(Expr::Func(ScalarFunc::Substring, args))
            }
            sql::Expr::Trim {
                expr,
                trim_where,
                trim_what,
                trim_characters,
            } => {
                if trim_characters.is_some() {
                    return Err("TRIM with a character list is not supported".to_string());
                }
                let func = match trim_where {
                    Some(sql::TrimWhereField::Leading) => ScalarFunc::Ltrim,
                    Some(sql::TrimWhereField::Trailing) => ScalarFunc::Rtrim,
                    Some(sql::TrimWhereField::Both) | None => ScalarFunc::Trim,
                };
                let mut args = vec![self.convert(expr, allow_agg)?];
                if let Some(what) = trim_what {
                    args.push(self.convert(what, allow_agg)?);
                }
                Ok(Expr::Func(func, args))
            }
            sql::Expr::Function(func) => self.convert_function(func, allow_agg),
            other => Err(format!("Unsupported SQL expression: {}", other)),
        }
    }

    fn convert_function(&mut self, func: &sql::Function, allow_agg: bool) -> Result<Expr, String> {
        let name = func
            .name
            .0
            .iter()
            .filter_map(|p| p.as_ident())
            .map(|i| i.value.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(".");

        let arg_list = match &func.args {
            sql::FunctionArguments::List(list) => {
                if list.duplicate_treatment.is_some() {
                    return Err(format!("DISTINCT is not supported in {}", name));
                }
                list.args.clone()
            }
            sql::FunctionArguments::None => Vec::new(),
            sql::FunctionArguments::Subquery(_) => {
                return Err("Subqueries are not supported".to_string());
            }
        };

        let mut wildcard_arg = false;
        let mut args: Vec<Expr> = Vec::with_capacity(arg_list.len());
        for arg in &arg_list {
            match arg {
                sql::FunctionArg::Unnamed(sql::FunctionArgExpr::Expr(e)) => {
                    args.push(self.convert(e, false)?);
                }
                sql::FunctionArg::Unnamed(sql::FunctionArgExpr::Wildcard) => {
                    wildcard_arg = true;
                }
                _ => return Err(format!("Unsupported argument in {}", name)),
            }
        }

        let agg = match name.as_str() {
            "COUNT" => Some(AggFunc::Count),
            "SUM" => Some(AggFunc::Sum),
            "MIN" => Some(AggFunc::Min),
            "MAX" => Some(AggFunc::Max),
            "AVG" => Some(AggFunc::Avg),
            _ => None,
        };
        if let Some(agg_func) = agg {
            if !allow_agg {
                return Err(format!("{} is not allowed in the WHERE clause", name));
            }
            let arg = if wildcard_arg {
                if agg_func != AggFunc::Count {
                    return Err(format!("{}(*) is not supported", name));
                }
                None
            } else {
                if args.len() != 1 {
                    return Err(format!("{} takes exactly one argument", name));
                }
                Some(args.remove(0))
            };
            self.aggregates.push(AggSpec {
                func: agg_func,
                arg,
            });
            return Ok(Expr::Aggregate(self.aggregates.len() - 1));
        }

        if wildcard_arg {
            return Err(format!("Unsupported argument in {}", name));
        }

        let (scalar, min_args, max_args) = match name.as_str() {
            "LOWER" => (ScalarFunc::Lower, 1, 1),
            "UPPER" => (ScalarFunc::Upper, 1, 1),
            "TRIM" => (ScalarFunc::Trim, 1, 1),
            "LTRIM" => (ScalarFunc::Ltrim, 1, 1),
            "RTRIM" => (ScalarFunc::Rtrim, 1, 1),
            "CHAR_LENGTH" | "CHARACTER_LENGTH" | "LENGTH" => (ScalarFunc::CharLength, 1, 1),
            "SUBSTRING" | "SUBSTR" => (ScalarFunc::Substring, 2, 3),
            "COALESCE" => (ScalarFunc::Coalesce, 1, usize::MAX),
            "NULLIF" => (ScalarFunc::Nullif, 2, 2),
            "ABS" => (ScalarFunc::Abs, 1, 1),
            "CEIL" | "CEILING" => (ScalarFunc::Ceil, 1, 1),
            "FLOOR" => (ScalarFunc::Floor, 1, 1),
            "ROUND" => (ScalarFunc::Round, 1, 2),
            _ => return Err(format!("Unsupported function: {}", name)),
        };
        if args.len() < min_args || args.len() > max_args {
            return Err(format!("Wrong number of arguments to {}", name));
        }
        Ok(Expr::Func(scalar, args))
    }

    fn column_from_parts(&self, mut parts: Vec<String>) -> Expr {
        if parts.len() > 1 && self.table_names.contains(&parts[0].to_ascii_lowercase()) {
            parts.remove(0);
        }
        let name = parts.remove(0);
        Expr::Column { name, path: parts }
    }
}

fn path_parts(expr: &sql::Expr) -> Option<Vec<String>> {
    match expr {
        sql::Expr::Identifier(ident) => Some(vec![ident.value.clone()]),
        sql::Expr::CompoundIdentifier(idents) => {
            Some(idents.iter().map(|i| i.value.clone()).collect())
        }
        sql::Expr::Function(func)
            if matches!(func.args, sql::FunctionArguments::None)
                && func.parameters == sql::FunctionArguments::None
                && func.filter.is_none()
                && func.over.is_none() =>
        {
            Some(
                func.name
                    .0
                    .iter()
                    .filter_map(|p| p.as_ident())
                    .map(|i| i.value.clone())
                    .collect(),
            )
        }
        _ => None,
    }
}

fn escape_char_value(escape: &Option<sql::ValueWithSpan>) -> Result<Option<char>, String> {
    match escape.as_ref().map(|v| &v.value) {
        None => Ok(None),
        Some(sql::Value::SingleQuotedString(s)) => {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Ok(Some(c)),
                _ => Err("ESCAPE must be a single character".to_string()),
            }
        }
        Some(_) => Err("ESCAPE must be a single character".to_string()),
    }
}

fn literal_value(value: &sql::Value) -> Result<Expr, String> {
    match value {
        sql::Value::Number(n, _) => {
            if let Ok(i) = n.parse::<i64>() {
                Ok(Expr::Literal(Value::Int(i)))
            } else {
                n.parse::<f64>()
                    .map(|f| Expr::Literal(Value::Float(f)))
                    .map_err(|_| format!("Invalid numeric literal: {}", n))
            }
        }
        sql::Value::SingleQuotedString(s) | sql::Value::DoubleQuotedString(s) => {
            Ok(Expr::Literal(Value::Str(s.clone())))
        }
        sql::Value::Boolean(b) => Ok(Expr::Literal(Value::Bool(*b))),
        sql::Value::Null => Ok(Expr::Literal(Value::Null)),
        other => Err(format!("Unsupported literal: {}", other)),
    }
}

fn cast_target(data_type: &sql::DataType) -> Result<CastType, String> {
    match data_type {
        sql::DataType::Int(_)
        | sql::DataType::Integer(_)
        | sql::DataType::BigInt(_)
        | sql::DataType::SmallInt(_)
        | sql::DataType::TinyInt(_) => Ok(CastType::Int),
        sql::DataType::Float(_)
        | sql::DataType::Real
        | sql::DataType::Double(_)
        | sql::DataType::DoublePrecision
        | sql::DataType::Decimal(_)
        | sql::DataType::Numeric(_) => Ok(CastType::Float),
        sql::DataType::Varchar(_)
        | sql::DataType::Char(_)
        | sql::DataType::CharacterVarying(_)
        | sql::DataType::Character(_)
        | sql::DataType::Text
        | sql::DataType::String(_) => Ok(CastType::Str),
        sql::DataType::Boolean | sql::DataType::Bool => Ok(CastType::Bool),
        other => Err(format!("Unsupported CAST target type: {}", other)),
    }
}

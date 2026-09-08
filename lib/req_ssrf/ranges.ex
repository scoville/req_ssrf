defmodule ReqSSRF.Ranges do
  @moduledoc false

  @doc """
  Returns the pattern variables and the guard for one CIDR range.

  IPv4 ranges: four variables, IPv6 ranges: 8 variables.

  `range` is a range as returned by `InetCidr.parse_cidr!/1`.

  For `100.64.0.0/10` the guard is:

      a >= 100 and a <= 100 and b >= 64 and b <= 127 and
        c >= 0 and c <= 255 and d >= 0 and d <= 255
  """
  def __clause__({start, finish, _prefix}) do
    elements = Macro.generate_arguments(tuple_size(start), __MODULE__)

    guard =
      [elements, Tuple.to_list(start), Tuple.to_list(finish)]
      |> Enum.zip()
      |> Enum.map(fn {element, low, high} ->
        quote do
          unquote(element) >= unquote(low) and unquote(element) <= unquote(high)
        end
      end)
      |> Enum.reduce(fn test, guard ->
        quote do
          unquote(guard) and unquote(test)
        end
      end)

    {elements, guard}
  end
end
